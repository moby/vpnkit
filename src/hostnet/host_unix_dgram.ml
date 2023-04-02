let src =
  let src = Logs.Src.create "Datagram" ~doc:"Host SOCK_DGRAM implementation" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

type flow = {
  (* SOCK_DGRAM socket. Ethernet frames are sent and received using send(2) and recv(2) *)
  fd : Unix.file_descr;
  (* A transmit queue. Packets are transmitted asynchronously by a background thread. *)
  send_q : Cstruct.t Queue.t;
  mutable send_done : bool;
  mutable send_len : int;
  send_waiters : unit Lwt.u Queue.t;
  send_m : Mutex.t;
  send_c : Condition.t;
  (* A receive queue. Packets are received asynchronously by a background thread. *)
  recv_q : Cstruct.t Queue.t;
  (* Amount of data currently queued *)
  mutable recv_len : int;
  recv_m : Mutex.t;
  (* Signalled when there is space in the queue *)
  recv_c : Condition.t;
  (* If the receive queue is empty then an Lwt thread can block itself here and will be woken up
     by the next packet arrival. If there is no waiting Lwt thread then packets are queued. *)
  mutable recv_u : Cstruct.t Lwt.u option;
  mtu : int;
}

let max_buffer = Constants.mib

exception Done

let send_thread t =
  try
    while true do
      Mutex.lock t.send_m;
      while Queue.is_empty t.send_q && not t.send_done do
        Condition.wait t.send_c t.send_m
      done;
      if t.send_done then raise Done;
      let to_send = Queue.copy t.send_q in
      Queue.clear t.send_q;
      t.send_len <- 0;
      let to_wake = Queue.copy t.send_waiters in
      Queue.clear t.send_waiters;
      Luv_lwt.in_lwt_async (fun () ->
          (* Wake up all blocked calls to send *)
          Queue.iter (fun u -> Lwt.wakeup_later u ()) to_wake);
      Mutex.unlock t.send_m;
      Queue.iter
        (fun packet ->
          try
            let n = Utils.cstruct_send t.fd packet in
            Log.debug (fun f -> f "send %d" n);
            let len = Cstruct.length packet in
            if n <> len then
              Log.warn (fun f ->
                  f "Utils.cstruct_send packet length %d but sent only %d" len n);
            t.send_len <- t.send_len - len
          with Unix.Unix_error (Unix.ENOBUFS, _, _) ->
            (* If we're out of buffer space we have to drop the packet *)
            Log.warn (fun f -> f "ENOBUFS: dropping packet"))
        to_send
    done
  with
  | Unix.Unix_error (Unix.EBADF, _, _) ->
      Log.info (fun f ->
          f "send: EBADFD: connection has been closed, stopping thread")
  | Done -> Log.info (fun f -> f "send: fd has been closed, stopping thread")
  | Unix.Unix_error (Unix.ECONNREFUSED, _, _) ->
      Log.info (fun f -> f "send: ECONNREFUSED: stopping thread")

let receive_thread t =
  try
    (* Many packets are small ACKs so cache an allocated buffer *)
    let allocation_size = Constants.mib in
    let recv_buffer = ref (Cstruct.create allocation_size) in
    while true do
      if Cstruct.length !recv_buffer < t.mtu then
        recv_buffer := Cstruct.create allocation_size;
      let n = Utils.cstruct_recv t.fd !recv_buffer in
      let packet = Cstruct.sub !recv_buffer 0 n in
      recv_buffer := Cstruct.shift !recv_buffer n;
      Log.debug (fun f -> f "recv %d" n);
      Mutex.lock t.recv_m;
      let handled = ref false in
      while not !handled do
        match t.recv_u with
        | None ->
            (* No-one is waiting so consider queueing the packet *)
            if n + t.recv_len > max_buffer then Condition.wait t.recv_c t.recv_m
              (* Note we need to check t.recv_u again *)
            else (
              Queue.push packet t.recv_q;
              t.recv_len <- t.recv_len + n;
              handled := true)
        | Some waiter ->
            (* A caller is blocked in recv already *)
            Luv_lwt.in_lwt_async (fun () -> Lwt.wakeup_later waiter packet);
            t.recv_u <- None;
            handled := true
      done;
      (* Is someone already waiting *)
      Mutex.unlock t.recv_m
    done
  with
  | Unix.Unix_error (Unix.EBADF, _, _) ->
      Log.info (fun f ->
          f "recv: EBADFD: connection has been closed, stopping thread")
  | Unix.Unix_error (Unix.ECONNREFUSED, _, _) ->
      Log.info (fun f -> f "recv: ECONNREFUSED: stopping thread")

let of_bound_fd ?(mtu = 65536) fd =
  Log.info (fun f -> f "SOCK_DGRAM interface using MTU %d" mtu);
  let t =
    {
      fd;
      send_q = Queue.create ();
      send_done = false;
      send_len = 0;
      send_waiters = Queue.create ();
      send_m = Mutex.create ();
      send_c = Condition.create ();
      recv_q = Queue.create ();
      recv_len = 0;
      recv_m = Mutex.create ();
      recv_c = Condition.create ();
      recv_u = None;
      mtu;
    }
  in
  let (_ : Thread.t) = Thread.create (fun () -> send_thread t) () in
  let (_ : Thread.t) = Thread.create (fun () -> receive_thread t) () in
  Lwt.return t

let send flow buf =
  let len = Cstruct.length buf in
  let rec loop () =
    Mutex.lock flow.send_m;
    if flow.send_len + len > max_buffer then (
      (* Too much data is queued. We will wait and this will add backpressure *)
      let t, u = Lwt.wait () in
      Queue.push u flow.send_waiters;
      Mutex.unlock flow.send_m;
      let open Lwt.Infix in
      t >>= fun () -> loop ())
    else (
      Queue.push buf flow.send_q;
      flow.send_len <- flow.send_len + len;
      Condition.signal flow.send_c;
      Mutex.unlock flow.send_m;
      Lwt.return_unit)
  in
  loop ()

let recv flow =
  Mutex.lock flow.recv_m;
  if not (Queue.is_empty flow.recv_q) then (
    (* A packet is already queued *)
    let packet = Queue.pop flow.recv_q in
    flow.recv_len <- flow.recv_len - Cstruct.length packet;
    Condition.signal flow.recv_c;
    Mutex.unlock flow.recv_m;
    Lwt.return packet)
  else (
    (* The TCP stack should only call recv serially, otherwise packets will be permuted *)
    assert (flow.recv_u = None);
    let t, u = Lwt.wait () in
    flow.recv_u <- Some u;
    Condition.signal flow.recv_c;
    Mutex.unlock flow.recv_m;
    (* Wait for a packet to arrive *)
    t)

let close flow =
  Mutex.lock flow.send_m;
  flow.send_done <- true;
  Condition.signal flow.send_c;
  Mutex.unlock flow.send_m;
  Unix.close flow.fd

let%test_unit "socketpair" =
  if Sys.os_type <> "Win32" then
    let a, b = Unix.socketpair Unix.PF_UNIX Unix.SOCK_DGRAM 0 in
    Lwt_main.run
      (let open Lwt.Infix in
      of_bound_fd a >>= fun a_flow ->
      of_bound_fd b >>= fun b_flow ->
      let rec loop () =
        Lwt.catch
          (fun () ->
            send a_flow (Cstruct.of_string "hello") >>= fun () ->
            Lwt.return true)
          (function
            | Unix.Unix_error (Unix.ENOTCONN, _, _) -> Lwt.return false
            | e -> Lwt.fail e)
        >>= function
        | false -> Lwt.return_unit
        | true -> Lwt_unix.sleep 1. >>= fun () -> loop ()
      in
      let _ = loop () in
      recv b_flow >>= fun buf ->
      let n = Cstruct.length buf in
      if n <> 5 then failwith (Printf.sprintf "recv returned %d, expected 5" n);
      let received = Cstruct.(to_string (sub buf 0 n)) in
      if received <> "hello" then
        failwith
          (Printf.sprintf "recv returned '%s', expected 'hello'" received);
      Printf.fprintf stderr "closing\n";
      close a_flow;
      close b_flow;
      Lwt.return_unit)

type error = [ `Closed | `Msg of string ]

let pp_error ppf = function
  | `Closed -> Fmt.string ppf "Closed"
  | `Msg m -> Fmt.string ppf m

type write_error = error

let pp_write_error = pp_error

open Lwt.Infix

let read t =
  recv t >>= fun buf ->
  let n = Cstruct.length buf in
  if n = 0 then Lwt.return @@ Ok `Eof else Lwt.return @@ Ok (`Data buf)

let read_into _t _buf =
  Lwt.return (Error (`Msg "read_into not implemented for SOCK_DGRAM"))

let write t buf = send t buf >>= fun () -> Lwt.return @@ Ok ()

let writev t bufs =
  let buf = Cstruct.concat bufs in
  write t buf

let close t =
  close t;
  Lwt.return_unit

(* A server listens on a Unix domain socket for connections and then receives SOCK_DGRAM
   file descriptors. In case someone connects and doesn't know the protocol we have a text
   error message describing what the socket is really for. *)
type server = { fd : Unix.file_descr }
type address = string

let magic = "VMNET"

let error_message =
  "This socket receives SOCK_DGRAM file descriptors for sending and receiving \
   ethernet frames.\n\
   It cannot be used directly.\n"

let success_message = "OK"

(* For low-frequency tasks like binding a listening socket, we fork a pthread for one request. *)
let run_in_pthread f =
  let t, u = Lwt.task () in
  let (_ : Thread.t) =
    Thread.create
      (fun () ->
        try
          let result = f () in
          Luv_lwt.in_lwt_async (fun () -> Lwt.wakeup_later u result)
        with e -> Luv_lwt.in_lwt_async (fun () -> Lwt.wakeup_exn u e))
      ()
  in
  t

let finally f g =
  try
    let result = f () in
    g ();
    result
  with e ->
    g ();
    raise e

let connect address =
  let open Lwt.Infix in
  run_in_pthread (fun () ->
      try
        let s = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
        finally
          (fun () ->
            Unix.connect s (Unix.ADDR_UNIX address);
            let a, b = Unix.socketpair Unix.PF_UNIX Unix.SOCK_DGRAM 0 in
            (* We will send a and keep b. *)
            finally
              (fun () ->
                try
                  let (_ : int) =
                    Fd_send_recv.send_fd s (Bytes.of_string magic) 0
                      (String.length magic) [] a
                  in
                  let buf = Bytes.create (String.length error_message) in
                  let n = Unix.read s buf 0 (Bytes.length buf) in
                  let response = Bytes.sub buf 0 n |> Bytes.to_string in
                  if response <> success_message then
                    failwith ("Host_unix_dgram.connect: " ^ response);
                  Ok b
                with e ->
                  Unix.close b;
                  raise e)
              (fun () -> Unix.close a))
          (fun () -> Unix.close s)
      with e -> Error e)
  >>= function
  | Ok fd -> of_bound_fd fd
  | Error e -> Lwt.fail e

let bind ?description:_ address =
  let open Lwt.Infix in
  run_in_pthread (fun () ->
      try
        let s = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
        try
          Unix.bind s (Unix.ADDR_UNIX address);
          Unix.listen s 5;
          Ok s
        with e ->
          Unix.close s;
          Error e
      with e -> Error e)
  >>= function
  | Ok fd -> Lwt.return { fd }
  | Error e -> Lwt.fail e

let listen server cb =
  let (_ : Thread.t) =
    Thread.create
      (fun () ->
        while true do
          let fd, _ = Unix.accept server.fd in
          let reply message =
            let m = Bytes.of_string message in
            let (_ : int) = Unix.write fd m 0 (Bytes.length m) in
            ()
          in
          finally
            (fun () ->
              let result = Bytes.make 8 '\000' in
              let n, _, received_fd =
                try Fd_send_recv.recv_fd fd result 0 (Bytes.length result) []
                with e ->
                  (* No passed fd probably means the caller doesn't realise what this socket is for. *)
                  reply error_message;
                  raise e
              in
              let actual_magic = Bytes.sub result 0 n |> Bytes.to_string in
              let ok = actual_magic = magic in
              let () =
                try reply @@ if ok then success_message else error_message
                with e ->
                  Unix.close received_fd;
                  raise e
              in
              if ok then
                Luv_lwt.in_lwt_async (fun () ->
                    Lwt.async (fun () ->
                        of_bound_fd received_fd >>= fun flow -> cb flow)))
            (fun () -> Unix.close fd)
        done)
      ()
  in
  ()

let shutdown server = run_in_pthread (fun () -> Unix.close server.fd)

let%test_unit "host_unix_dgram" =
  if Sys.os_type <> "Win32" then
    Lwt_main.run
      (let address = "/tmp/host_unix_dgram.sock" in
       (try Unix.unlink address with Unix.Unix_error (Unix.ENOENT, _, _) -> ());
       bind address >>= fun server ->
       listen server (fun flow ->
           recv flow >>= fun buf ->
           let n = Cstruct.length buf in
           send flow (Cstruct.sub buf 0 n));
       connect address >>= fun flow ->
       let message = "hello" in
       let buf = Cstruct.create (String.length message) in
       Cstruct.blit_from_string message 0 buf 0 (String.length message);
       send flow buf >>= fun () ->
       recv flow >>= fun buf ->
       let n = Cstruct.length buf in
       if n <> String.length message then
         failwith
           (Printf.sprintf "n (%d) <> String.length message (%d)" n
              (String.length message));
       let response = Cstruct.to_string buf in
       if message <> response then
         failwith
           (Printf.sprintf "message (%s) <> response (%s)" message response);
       close flow)

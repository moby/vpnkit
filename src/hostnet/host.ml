open Lwt.Infix

let src =
  let src = Logs.Src.create "Luv" ~doc:"Host interface based on Luv" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let log_exception_continue description f =
  let to_string = function Failure x -> x | e -> Printexc.to_string e in
  Lwt.catch
    (fun () -> f ())
    (fun e ->
      Log.warn (fun f -> f "%s: %s" description (to_string e));
      Lwt.return ())

let make_sockaddr (ip, port) =
  match ip with
  | Ipaddr.V4 _ -> Luv.Sockaddr.ipv4 (Ipaddr.to_string ip) port
  | Ipaddr.V6 _ -> Luv.Sockaddr.ipv6 (Ipaddr.to_string ip) port

let parse_sockaddr sockaddr =
  match (Luv.Sockaddr.to_string sockaddr, Luv.Sockaddr.port sockaddr) with
  | Some ip, Some port -> Ok (Ipaddr.of_string_exn ip, port)
  | None, _ ->
      Log.err (fun f -> f "unable to parse sockaddr: IP is None");
      Error `UNKNOWN
  | _, None ->
      Log.err (fun f -> f "unable to parse sockaddr: port is None");
      Error `UNKNOWN

let string_of_address (dst, dst_port) =
  Ipaddr.to_string dst ^ ":" ^ string_of_int dst_port

module Common = struct
  (** FLOW boilerplate *)

  type 'a io = 'a Lwt.t

  type buffer = Cstruct.t

  type error = [ `Msg of string ]

  type write_error = [ Mirage_flow.write_error | error ]

  let pp_error ppf (`Msg x) = Fmt.string ppf x

  let pp_write_error ppf = function
    | #Mirage_flow.write_error as e -> Mirage_flow.pp_write_error ppf e
    | #error as e -> pp_error ppf e
end

module Sockets = struct
  module Datagram = struct
    type address = Ipaddr.t * int

    let string_of_address = string_of_address

    module Udp = struct
      include Common

      type flow = {
        idx : int option;
        label : string;
        description : string;
        mutable fd : Luv.UDP.t option;
        mutable already_read : Cstruct.t option;
        sockaddr : Luv.Sockaddr.t;
        address : address;
      }

      type address = Ipaddr.t * int

      let string_of_flow t = Fmt.strf "udp -> %s" (string_of_address t.address)

      let of_fd ?idx ?read_buffer_size:_ ?(already_read = None) ~description
          sockaddr address fd =
        let label =
          match fst address with
          | Ipaddr.V4 _ -> "UDPv4"
          | Ipaddr.V6 _ -> "UDPv6"
        in
        {
          idx;
          label;
          description;
          fd = Some fd;
          already_read;
          sockaddr;
          address;
        }

      let connect ?read_buffer_size address =
        let description = "udp:" ^ string_of_address address in
        let label =
          match address with
          | Ipaddr.V4 _, _ -> "UDPv4"
          | Ipaddr.V6 _, _ -> "UDPv6"
        in
        Luv_lwt.in_luv (fun return ->
            match Connection_limit.register description with
            | Error e -> return (Error e)
            | Ok idx -> (
                match Luv.UDP.init () with
                | Error err ->
                    Connection_limit.deregister idx;
                    return (Error (`Msg (Luv.Error.strerror err)))
                | Ok fd -> (
                    match make_sockaddr address with
                    | Error err ->
                        Connection_limit.deregister idx;
                        Luv.Handle.close fd (fun () ->
                            return (Error (`Msg (Luv.Error.strerror err))))
                    | Ok sockaddr -> return (Ok (fd, sockaddr, idx)))))
        >>= function
        | Error (`Msg m) ->
            let msg =
              Fmt.strf "Socket.%s.connect %s: %s" label
                (string_of_address address)
                m
            in
            Log.info (fun f -> f "%s" msg);
            Lwt.return (Error (`Msg msg))
        | Ok (fd, sockaddr, idx) ->
            Lwt.return
              (Ok
                 (of_fd ~idx ?read_buffer_size ~description sockaddr address fd))

      let read t =
        match (t.fd, t.already_read) with
        | None, _ -> Lwt.return (Ok `Eof)
        | Some _, Some data when Cstruct.len data > 0 ->
            t.already_read <- Some (Cstruct.sub data 0 0);
            (* next read is `Eof *)
            Lwt.return (Ok (`Data data))
        | Some _, Some _ -> Lwt.return (Ok `Eof)
        | Some fd, None ->
            Luv_lwt.in_luv (fun return ->
                Luv.UDP.recv_start fd (function
                  | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
                  | Ok (_, None, _) -> () (* EAGAIN, to be ignored *)
                  | Ok (buf, Some peer, flags) -> (
                      if List.mem `PARTIAL flags then
                        Log.warn (fun f ->
                            f
                              "Socket.%s.read: dropping partial response \
                               (buffer was %d bytes)"
                              t.label (Luv.Buffer.size buf))
                      else
                        match parse_sockaddr peer with
                        | Error _ ->
                            Log.warn (fun f ->
                                f
                                  "Socket.%s.read: dropping response from \
                                   unknown peer"
                                  t.label)
                        | Ok address when address <> t.address ->
                            Log.warn (fun f ->
                                f
                                  "Socket.%s.read: dropping response from %s \
                                   since we're connected to %s"
                                  t.label
                                  (string_of_address address)
                                  (string_of_address t.address))
                        | Ok _ -> (
                            (* We got one! *)
                            match Luv.UDP.recv_stop fd with
                            | Error err ->
                                return (Error (`Msg (Luv.Error.strerror err)))
                            | Ok () ->
                                return (Ok (`Data (Cstruct.of_bigarray buf)))))))

      let writev t bufs =
        match t.fd with
        | None -> Lwt.return (Error `Closed)
        | Some fd ->
            let buffers =
              List.map
                (fun buf ->
                  Luv.Buffer.sub buf.Cstruct.buffer ~offset:buf.Cstruct.off
                    ~length:buf.Cstruct.len)
                bufs
            in
            Luv_lwt.in_luv (fun return ->
                Luv.UDP.send fd buffers t.sockaddr (function
                  | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
                  | Ok () -> return (Ok ())))

      let write t buf = writev t [ buf ]

      let close t =
        match t.fd with
        | None -> Lwt.return_unit
        | Some fd ->
            t.fd <- None;
            Log.debug (fun f ->
                f "Socket.%s.close: %s" t.label (string_of_flow t));
            Luv_lwt.in_luv (fun return ->
                (match t.idx with
                | Some idx -> Connection_limit.deregister idx
                | None -> ());
                Luv.Handle.close fd return)
            >>= fun () -> Lwt.return_unit

      let shutdown_read _t = Lwt.return_unit

      let shutdown_write _t = Lwt.return_unit

      type server = {
        idx : int;
        label : string;
        fd : Luv.UDP.t;
        fd_mutex : Lwt_mutex.t;
        mutable closed : bool;
        mutable disable_connection_tracking : bool;
      }

      let make ~idx ~label fd =
        let fd_mutex = Lwt_mutex.create () in
        {
          idx;
          label;
          fd;
          fd_mutex;
          closed = false;
          disable_connection_tracking = false;
        }

      let disable_connection_tracking server =
        server.disable_connection_tracking <- true

      let bind ?(description = "") (ip, port) =
        let label =
          match ip with Ipaddr.V4 _ -> "UDPv4" | Ipaddr.V6 _ -> "UDPv6"
        in
        let description =
          Fmt.strf "udp:%a:%d %s" Ipaddr.pp ip port description
        in
        Luv_lwt.in_luv (fun return ->
            match Connection_limit.register description with
            | Error e -> return (Error e)
            | Ok idx -> (
                match Luv.UDP.init () with
                | Error err ->
                    Connection_limit.deregister idx;
                    return (Error (`Msg (Luv.Error.strerror err)))
                | Ok fd -> (
                    match make_sockaddr (ip, port) with
                    | Error err ->
                        Connection_limit.deregister idx;
                        Luv.Handle.close fd (fun () ->
                            return (Error (`Msg (Luv.Error.strerror err))))
                    | Ok sockaddr -> (
                        match Luv.UDP.bind ~reuseaddr:true fd sockaddr with
                        | Error err ->
                            Connection_limit.deregister idx;
                            Luv.Handle.close fd (fun () ->
                                return (Error (`Msg (Luv.Error.strerror err))))
                        | Ok () -> return (Ok (fd, idx))))))
        >>= function
        | Error (`Msg m) ->
            let msg =
              Fmt.strf "Socket.%s.bind %s:%d: %s" label (Ipaddr.to_string ip)
                port m
            in
            Log.err (fun f -> f "%s" msg);
            Lwt.fail_with msg
        | Ok (fd, idx) -> Lwt.return (make ~idx ~label fd)

      let of_bound_fd ?read_buffer_size:_ fd =
        Luv_lwt.in_luv (fun return ->
            match Luv_unix.Os_fd.Socket.from_unix fd with
            | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
            | Ok socket -> (
                match Luv.UDP.init () with
                | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
                | Ok udp -> (
                    match Luv.UDP.open_ udp socket with
                    | Error err ->
                        Luv.Handle.close udp ignore;
                        return (Error (`Msg (Luv.Error.strerror err)))
                    | Ok () -> (
                        match Luv.UDP.getsockname udp with
                        | Error err ->
                            Luv.Handle.close udp ignore;
                            return (Error (`Msg (Luv.Error.strerror err)))
                        | Ok sockaddr ->
                            let ip =
                              match Luv.Sockaddr.to_string sockaddr with
                              | None -> "None"
                              | Some x -> x
                            in
                            let port =
                              match Luv.Sockaddr.port sockaddr with
                              | None -> "None"
                              | Some x -> string_of_int x
                            in
                            let label = "udp:" ^ ip ^ ":" ^ port in
                            let idx =
                              Connection_limit.register_no_limit "udp"
                            in
                            return (Ok (idx, label, udp))))))
        >>= function
        | Error (`Msg m) -> Lwt.fail_with m
        | Ok (idx, label, udp) -> Lwt.return (make ~idx ~label udp)

      let getsockname { fd; _ } =
        Luv_lwt.in_luv (fun return ->
            match Luv.UDP.getsockname fd with
            | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
            | Ok sockaddr -> (
                match parse_sockaddr sockaddr with
                | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
                | Ok (ip, port) -> return (Ok (ip, port))))
        >>= function
        | Error (`Msg m) -> Lwt.fail_with m
        | Ok x -> Lwt.return x

      let shutdown server =
        if not server.closed then (
          server.closed <- true;
          Luv_lwt.in_luv (fun return ->
              Connection_limit.deregister server.idx;
              Luv.Handle.close server.fd return)
          >>= fun () -> Lwt.return_unit)
        else Lwt.return_unit

      let recvfrom server buf =
        let buf =
          Luv.Buffer.sub buf.Cstruct.buffer ~offset:buf.Cstruct.off
            ~length:buf.Cstruct.len
        in
        Luv_lwt.in_luv (fun return ->
            Luv.UDP.recv_start
              ~allocate:(fun _ -> buf)
              server.fd
              (function
                | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
                | Ok (_, None, _) -> () (* EAGAIN, to be ignored *)
                | Ok (buf, Some peer, flags) -> (
                    if List.mem `PARTIAL flags then
                      Log.warn (fun f ->
                          f
                            "Socket.%s.read: dropping partial response (buffer \
                             was %d bytes)"
                            server.label (Luv.Buffer.size buf))
                    else
                      match parse_sockaddr peer with
                      | Error _ ->
                          Log.warn (fun f ->
                              f
                                "Socket.%s.read: dropping response from \
                                 unknown peer"
                                server.label)
                      | Ok address -> (
                          (* We got one! *)
                          match Luv.UDP.recv_stop server.fd with
                          | Error err ->
                              return (Error (`Msg (Luv.Error.strerror err)))
                          | Ok () -> return (Ok (Luv.Buffer.size buf, address)))
                    )))
        >>= function
        | Error (`Msg m) -> Lwt.fail_with m
        | Ok (size, address) -> Lwt.return (size, address)

      let listen t flow_cb =
        let rec loop () =
          Lwt.catch
            (fun () ->
              (* Allocate a fresh buffer because the packet will be
                 processed in a background thread *)
              let buffer = Cstruct.create Constants.max_udp_length in
              recvfrom t buffer >>= fun (n, address) ->
              let data = Cstruct.sub buffer 0 n in
              (* construct a flow with this buffer available for reading *)
              (* No new fd so no new idx *)
              let description = Fmt.strf "udp:%s" (string_of_address address) in
              match make_sockaddr address with
              | Error _ ->
                  Log.warn (fun f ->
                      f "Socket.%s.listen: dropping response from unknown peer"
                        t.label);
                  Lwt.return true
              | Ok sockaddr ->
                  let flow =
                    of_fd ~description ~read_buffer_size:0
                      ~already_read:(Some data) sockaddr address t.fd
                  in
                  Lwt.async (fun () ->
                      Lwt.catch
                        (fun () -> flow_cb flow)
                        (fun e ->
                          Log.info (fun f ->
                              f "Socket.%s.listen callback caught: %s" t.label
                                (Printexc.to_string e));
                          Lwt.return_unit));
                  Lwt.return true)
            (fun e ->
              Log.info (fun f ->
                  f "Socket.%s.listen caught %s shutting down server" t.label
                    (Printexc.to_string e));
              Lwt.return false)
          >>= function
          | false -> Lwt.return_unit
          | true -> loop ()
        in
        Lwt.async loop

      let sendto server (ip, port) ?(ttl = 64) buf =
        (* Avoid a race between the setSocketTTL and the send_ba *)
        Lwt_mutex.with_lock server.fd_mutex (fun () ->
            let buf =
              Luv.Buffer.sub buf.Cstruct.buffer ~offset:buf.Cstruct.off
                ~length:buf.Cstruct.len
            in
            Luv_lwt.in_luv (fun return ->
                match make_sockaddr (ip, port) with
                | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
                | Ok sockaddr -> (
                    match Luv.UDP.set_ttl server.fd ttl with
                    | Error err ->
                        return (Error (`Msg (Luv.Error.strerror err)))
                    | Ok () ->
                        Luv.UDP.send server.fd [ buf ] sockaddr (function
                          | Error err ->
                              return (Error (`Msg (Luv.Error.strerror err)))
                          | Ok () -> return (Ok ())))))
        >>= function
        | Error (`Msg m) ->
            let msg =
              Fmt.strf "%s.sendto %s: %s" server.label
                (string_of_address (ip, port))
                m
            in
            Log.info (fun f -> f "%s" msg);
            Lwt.fail_with m
        | Ok () -> Lwt.return_unit
    end
  end

  module Stream = struct
    (* Common across TCP and Pipes *)

    let read_into fd buf =
      Luv_lwt.in_luv (fun return ->
          let buffer =
            Luv.Buffer.sub buf.Cstruct.buffer ~offset:buf.Cstruct.off
              ~length:buf.Cstruct.len
          in
          Luv.Stream.read_start
            ~allocate:(fun _suggested -> buffer)
            fd
            (function
              | Ok b -> (
                  let n = Luv.Buffer.size buffer - Luv.Buffer.size b in
                  if n == 0 then
                    match Luv.Stream.read_stop fd with
                    | Ok () -> return (Ok (`Data ()))
                    | Error err ->
                        return (Error (`Msg (Luv.Error.strerror err))))
              | Error `EOF -> return (Ok `Eof)
              | Error err -> return (Error (`Msg (Luv.Error.strerror err)))))

    let read fd =
      Luv_lwt.in_luv (fun return ->
          Luv.Stream.read_start fd (function
            | Ok buf -> (
                match Luv.Stream.read_stop fd with
                | Ok () -> return (Ok (`Data (Cstruct.of_bigarray buf)))
                | Error err -> return (Error (`Msg (Luv.Error.strerror err))))
            | Error `EOF -> return (Ok `Eof)
            | Error err -> return (Error (`Msg (Luv.Error.strerror err)))))

    let writev fd bufs =
      let buffers =
        List.map
          (fun buf ->
            Luv.Buffer.sub buf.Cstruct.buffer ~offset:buf.Cstruct.off
              ~length:buf.Cstruct.len)
          bufs
      in
      Luv_lwt.in_luv (fun return ->
          let rec loop buffers =
            if Luv.Buffer.total_size buffers == 0 then return (Ok ())
            else
              Luv.Stream.write fd buffers (fun r n ->
                  match r with
                  | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
                  | Ok () -> loop (Luv.Buffer.drop buffers n))
          in
          loop buffers)

    module Tcp = struct
      include Common

      type address = Ipaddr.t * int

      let get_test_address () =
        let localhost = Unix.inet_addr_of_string "127.0.0.1" in
        let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
        Unix.bind s (Unix.ADDR_INET (localhost, 0));
        let sa = Unix.getsockname s in
        Unix.close s;
        match sa with
        | Unix.ADDR_INET (_, port) -> (Ipaddr.of_string_exn "127.0.0.1", port)
        | _ -> failwith "get_test_address"

      type flow = {
        idx : int;
        label : string;
        description : string;
        fd : Luv.TCP.t;
        mutable closed : bool;
      }

      let of_fd ~label ~idx ?read_buffer_size:_ ~description fd =
        let closed = false in
        { idx; label; description; fd; closed }

      let connect ?read_buffer_size:_ (ip, port) =
        let description = Fmt.strf "tcp:%a:%d" Ipaddr.pp ip port in
        let label =
          match ip with Ipaddr.V4 _ -> "TCPv4" | Ipaddr.V6 _ -> "TCPv6"
        in

        Luv_lwt.in_luv (fun return ->
            match Connection_limit.register description with
            | Error _ ->
                return
                  (Error
                     (`Msg
                       (Printf.sprintf "Socket.%s.connect: hit connection limit"
                          label)))
            | Ok idx -> (
                match Luv.TCP.init () with
                | Error err ->
                    Connection_limit.deregister idx;
                    return (Error (`Msg (Luv.Error.strerror err)))
                | Ok fd -> (
                    match make_sockaddr (ip, port) with
                    | Error err ->
                        Connection_limit.deregister idx;
                        Luv.Handle.close fd (fun () ->
                            return (Error (`Msg (Luv.Error.strerror err))))
                    | Ok sockaddr ->
                        Luv.TCP.connect fd sockaddr (function
                          | Error err ->
                              Connection_limit.deregister idx;
                              Luv.Handle.close fd (fun () ->
                                  return (Error (`Msg (Luv.Error.strerror err))))
                          | Ok () -> return (Ok (fd, idx))))))
        >>= function
        | Error (`Msg m) ->
            let msg =
              Fmt.strf "Socket.%s.connect %s:%d: %s" label (Ipaddr.to_string ip)
                port m
            in
            Log.info (fun f -> f "%s" msg);
            Lwt.return (Error (`Msg msg))
        | Ok (fd, idx) -> Lwt.return (Ok (of_fd ~description ~idx ~label fd))

      let shutdown_read _ = Lwt.return ()

      let shutdown_write { label; fd; closed; _ } =
        if not closed then
          Luv_lwt.in_luv (fun return ->
              Luv.Stream.shutdown fd (function
                | Error err ->
                    Log.warn (fun f ->
                        f "Socket.%s.shutdown_write: %s" label
                          (Luv.Error.strerror err));
                    return ()
                | Ok () -> return ()))
        else Lwt.return_unit

      let read_into t buf = read_into t.fd buf

      let read t = read t.fd

      let writev t bufs = writev t.fd bufs

      let write t buf = writev t [ buf ]

      let close t =
        if not t.closed then (
          t.closed <- true;
          Luv_lwt.in_luv (fun return ->
              Connection_limit.deregister t.idx;
              Luv.Handle.close t.fd return))
        else Lwt.return_unit

      type server = {
        label : string;
        mutable listening_fds : (int * (Ipaddr.t * int) * Luv.TCP.t) list;
        mutable disable_connection_tracking : bool;
      }

      let label_of ip =
        match ip with Ipaddr.V4 _ -> "TCPv4" | Ipaddr.V6 _ -> "TCPv6"

      let make ?read_buffer_size:_ ip listening_fds =
        let label = label_of ip in
        { label; listening_fds; disable_connection_tracking = false }

      let disable_connection_tracking server =
        server.disable_connection_tracking <- true

      let getsockname server =
        match server.listening_fds with
        | [] -> Lwt.fail_with "socket is closed"
        | (_, (ip, port), _) :: _ -> Lwt.return (ip, port)

      let bind_one ?(description = "") (ip, port) =
        let label =
          match ip with Ipaddr.V4 _ -> "TCPv4" | Ipaddr.V6 _ -> "TCPv6"
        in
        let description =
          Fmt.strf "tcp:%a:%d %s" Ipaddr.pp ip port description
        in
        Luv_lwt.in_luv (fun return ->
            match Connection_limit.register description with
            | Error e -> return (Error e)
            | Ok idx -> (
                match Luv.TCP.init () with
                | Error err ->
                    Connection_limit.deregister idx;
                    return (Error (`Msg (Luv.Error.strerror err)))
                | Ok fd -> (
                    match make_sockaddr (ip, port) with
                    | Error err ->
                        Connection_limit.deregister idx;
                        Luv.Handle.close fd (fun () ->
                            return (Error (`Msg (Luv.Error.strerror err))))
                    | Ok sockaddr -> (
                        match Luv.TCP.bind fd sockaddr with
                        | Error err ->
                            Connection_limit.deregister idx;
                            Luv.Handle.close fd (fun () ->
                                return (Error (`Msg (Luv.Error.strerror err))))
                        | Ok () -> (
                            match Luv.TCP.getsockname fd with
                            | Error err ->
                                Connection_limit.deregister idx;
                                Luv.Handle.close fd (fun () ->
                                    return
                                      (Error (`Msg (Luv.Error.strerror err))))
                            | Ok sockaddr -> (
                                match Luv.Sockaddr.port sockaddr with
                                | None ->
                                    Connection_limit.deregister idx;
                                    Luv.Handle.close fd (fun () ->
                                        return
                                          (Error
                                             (`Msg
                                               "bound local port should not be \
                                                None")))
                                | Some port ->
                                    return (Ok (idx, label, fd, port))))))))
        >>= function
        | Error (`Msg m) ->
            let msg =
              Fmt.strf "Socket.%s.bind_one %s:%d: %s" label
                (Ipaddr.to_string ip) port m
            in
            Log.err (fun f -> f "%s" msg);
            Lwt.return (Error (`Msg m))
        | Ok x -> Lwt.return (Ok x)

      let bind ?description (ip, requested_port) =
        bind_one ?description (ip, requested_port) >>= function
        | Error (`Msg m) -> Lwt.fail_with m
        | Ok (idx, _label, fd, bound_port) ->
            (* On some systems localhost will resolve to ::1 first and this can
               cause performance problems (particularly on Windows). Perform a
               best-effort bind to the ::1 address. *)
            Lwt.catch
              (fun () ->
                if
                  Ipaddr.compare ip (Ipaddr.V4 Ipaddr.V4.localhost) = 0
                  || Ipaddr.compare ip (Ipaddr.V4 Ipaddr.V4.any) = 0
                then (
                  Log.debug (fun f ->
                      f "Attempting a best-effort bind of ::1:%d" bound_port);
                  bind_one (Ipaddr.(V6 V6.localhost), bound_port) >>= function
                  | Error (`Msg m) -> Lwt.fail_with m
                  | Ok (idx, _, fd, _) ->
                      Lwt.return [ (idx, (ip, bound_port), fd) ])
                else Lwt.return [])
              (fun e ->
                Log.debug (fun f ->
                    f "Ignoring failed bind to ::1:%d (%a)" bound_port Fmt.exn e);
                Lwt.return [])
            >|= fun extra -> make ip ((idx, (ip, bound_port), fd) :: extra)

      let shutdown server =
        let fds = server.listening_fds in
        server.listening_fds <- [];
        Lwt_list.iter_s
          (fun (idx, _, fd) ->
            Luv_lwt.in_luv (fun return ->
                Connection_limit.deregister idx;
                Luv.Handle.close fd return)
            >>= fun () -> Lwt.return_unit)
          fds

      let of_bound_fd ?read_buffer_size:_ fd =
        Luv_lwt.in_luv (fun return ->
            match Luv_unix.Os_fd.Socket.from_unix fd with
            | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
            | Ok socket -> (
                match Luv.TCP.init () with
                | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
                | Ok tcp -> (
                    match Luv.TCP.open_ tcp socket with
                    | Error err ->
                        Luv.Handle.close tcp (fun () ->
                            return (Error (`Msg (Luv.Error.strerror err))))
                    | Ok () -> (
                        match Luv.TCP.getsockname tcp with
                        | Error err ->
                            Luv.Handle.close tcp (fun () ->
                                return (Error (`Msg (Luv.Error.strerror err))))
                        | Ok sockaddr -> (
                            match Luv.Sockaddr.to_string sockaddr with
                            | None ->
                                Luv.Handle.close tcp (fun () ->
                                    return
                                      (Error
                                         (`Msg
                                           "TCP.getsockname returned no IP \
                                            address")))
                            | Some x -> (
                                match Ipaddr.of_string x with
                                | None ->
                                    Luv.Handle.close tcp (fun () ->
                                        return
                                          (Error
                                             (`Msg
                                               ("TCP.getsockname returned an \
                                                 invalid IP: " ^ x))))
                                | Some ip -> (
                                    match Luv.Sockaddr.port sockaddr with
                                    | None ->
                                        Luv.Handle.close tcp (fun () ->
                                            return
                                              (Error
                                                 (`Msg
                                                   "TCP.getsockname returned \
                                                    no port number")))
                                    | Some port ->
                                        let description =
                                          Printf.sprintf "tcp:%s:%d" x port
                                        in
                                        let idx =
                                          Connection_limit.register_no_limit
                                            description
                                        in
                                        return (Ok (idx, (ip, port), tcp)))))))))
        >>= function
        | Error (`Msg m) -> Lwt.fail_with m
        | Ok (idx, (ip, port), fd) ->
            Lwt.return (make ip [ (idx, (ip, port), fd) ])

      let listen server' cb =
        let handle_connection client label description idx =
          Luv_lwt.in_lwt_async (fun () ->
              Lwt.async (fun () ->
                  let flow = of_fd ~label ~idx ~description client in
                  Lwt.finalize
                    (fun () ->
                      log_exception_continue "TCP.listen" (fun () -> cb flow))
                    (fun () -> close flow)))
        in

        List.iter
          (fun (_, (ip, port), fd) ->
            Luv_lwt.in_luv_async (fun () ->
                Luv.Stream.listen fd (function
                  | Error err ->
                      Log.warn (fun f ->
                          f "TCP.listen: %s" (Luv.Error.strerror err))
                  | Ok () -> (
                      let description =
                        Fmt.strf "%s:%s:%d" server'.label (Ipaddr.to_string ip)
                          port
                      in
                      match Luv.TCP.init () with
                      | Error err ->
                          Log.err (fun f ->
                              f "TCP.init: %s" (Luv.Error.strerror err))
                      | Ok client -> (
                          let error msg err =
                            Log.warn (fun f ->
                                f "Socket.%s.listen %s: %s" server'.label msg
                                  (Luv.Error.strerror err));
                            Luv.Handle.close client ignore
                          in
                          match Luv.Stream.accept ~server:fd ~client with
                          | Error `EAGAIN -> Luv.Handle.close client ignore
                          | Error err -> error "accept" err
                          | Ok () -> (
                              match Luv.TCP.nodelay client true with
                              | Error err -> error "nodelay" err
                              | Ok () -> (
                                  match Luv.TCP.keepalive client (Some 1) with
                                  | Error err -> error "keepalive" err
                                  | Ok () -> (
                                      match
                                        ( Connection_limit.register description,
                                          server'.disable_connection_tracking )
                                      with
                                      | Ok idx, _ ->
                                          handle_connection client server'.label
                                            description idx
                                      | Error _, true ->
                                          let idx =
                                            Connection_limit.register_no_limit
                                              description
                                          in
                                          handle_connection client server'.label
                                            description idx
                                      | _, _ -> Luv.Handle.close client ignore))
                              ))))))
          server'.listening_fds
    end

    module Unix = struct
      include Common

      type address = string

      let get_test_address () =
        let i = Random.int 1_000_000 in
        if Sys.os_type == "Windows" then
          Printf.sprintf "\\\\.\\pipe\\vpnkittest%d" i
        else Printf.sprintf "/tmp/vpnkittest.%d" i

      type flow = {
        idx : int;
        description : string;
        fd : Luv.Pipe.t;
        mutable closed : bool;
      }

      let of_fd ~idx ?read_buffer_size:_ ~description fd =
        let closed = false in
        { idx; description; fd; closed }

      let unsafe_get_raw_fd _t = failwith "unsafe_get_raw_fd unimplemented"

      let connect ?read_buffer_size:_ path =
        let description = "unix:" ^ path in
        Luv_lwt.in_luv (fun return ->
            match Connection_limit.register description with
            | Error e -> return (Error e)
            | Ok idx -> (
                match Luv.Pipe.init () with
                | Error err ->
                    Connection_limit.deregister idx;
                    let msg =
                      Fmt.strf "Pipe.connect %s: %s" path
                        (Luv.Error.strerror err)
                    in
                    Log.err (fun f -> f "%s" msg);
                    return (Error (`Msg msg))
                | Ok fd ->
                    Luv.Pipe.connect fd path (function
                      | Error err ->
                          Connection_limit.deregister idx;
                          Luv.Handle.close fd (fun () ->
                              return (Error (`Msg (Luv.Error.strerror err))))
                      | Ok () -> return (Ok (idx, fd)))))
        >>= function
        | Error e -> Lwt.return (Error e)
        | Ok (idx, fd) -> Lwt.return (Ok (of_fd ~description ~idx fd))

      let shutdown_read _ = Lwt.return ()

      let shutdown_write { fd; closed; _ } =
        if not closed then
          Luv_lwt.in_luv (fun return ->
              Luv.Stream.shutdown fd (function
                | Error err ->
                    Log.warn (fun f ->
                        f "Pipe.shutdown_write: %s" (Luv.Error.strerror err));
                    return ()
                | Ok () -> return ()))
        else Lwt.return_unit

      let read_into t buf = read_into t.fd buf

      let read t = read t.fd

      let writev t bufs = writev t.fd bufs

      let write t buf = writev t [ buf ]

      let close t =
        if not t.closed then (
          t.closed <- true;
          Luv_lwt.in_luv (fun return ->
              Connection_limit.deregister t.idx;
              Luv.Handle.close t.fd return))
        else Lwt.return_unit

      type server = {
        idx : int;
        fd : Luv.Pipe.t;
        mutable closed : bool;
        mutable disable_connection_tracking : bool;
      }

      let bind ?(description = "") path =
        let description = Fmt.strf "unix:%s %s" path description in
        Luv_lwt.in_luv (fun return ->
            Luv.File.unlink path (fun _ ->
                match Connection_limit.register description with
                | Error e -> return (Error e)
                | Ok idx -> (
                    match Luv.Pipe.init () with
                    | Error err ->
                        Connection_limit.deregister idx;
                        return (Error (`Msg (Luv.Error.strerror err)))
                    | Ok fd -> (
                        match Luv.Pipe.bind fd path with
                        | Error err ->
                            Connection_limit.deregister idx;
                            Luv.Handle.close fd (fun () ->
                                return (Error (`Msg (Luv.Error.strerror err))))
                        | Ok () ->
                            return
                              (Ok
                                 {
                                   idx;
                                   fd;
                                   closed = false;
                                   disable_connection_tracking = false;
                                 })))))
        >>= function
        | Error (`Msg m) -> Lwt.fail_with m
        | Ok x -> Lwt.return x

      let getsockname server =
        Luv_lwt.in_luv (fun return -> return (Luv.Pipe.getsockname server.fd))
        >>= function
        | Ok path -> Lwt.return path
        | _ ->
            Lwt.fail (Invalid_argument "Unix.sockname passed a non-Unix socket")

      let disable_connection_tracking server =
        server.disable_connection_tracking <- true

      let listen ({ fd; _ } as server') cb =
        let handle_connection client description idx =
          Luv_lwt.in_lwt_async (fun () ->
              Lwt.async (fun () ->
                  let flow = of_fd ~idx ~description client in
                  Lwt.finalize
                    (fun () ->
                      log_exception_continue "Pipe.listen" (fun () -> cb flow))
                    (fun () -> close flow)))
        in

        Luv_lwt.in_luv_async (fun () ->
            let description =
              "unix:"
              ^
              match Luv.Pipe.getsockname fd with
              | Ok path -> path
              | Error err -> "(error " ^ Luv.Error.strerror err ^ ")"
            in
            Luv.Stream.listen fd (function
              | Error err ->
                  Log.warn (fun f ->
                      f "Pipe.listen: %s" (Luv.Error.strerror err))
              | Ok () -> (
                  match Luv.Pipe.init () with
                  | Error err ->
                      Log.err (fun f ->
                          f "Pipe.init: %s" (Luv.Error.strerror err))
                  | Ok client -> (
                      match Luv.Stream.accept ~server:fd ~client with
                      | Error `EAGAIN -> Luv.Handle.close client ignore
                      | Error err ->
                          Luv.Handle.close client ignore;
                          Log.warn (fun f ->
                              f "Pipe.accept: %s" (Luv.Error.strerror err))
                      | Ok () -> (
                          match
                            ( Connection_limit.register description,
                              server'.disable_connection_tracking )
                          with
                          | Ok idx, _ ->
                              handle_connection client description idx
                          | Error _, true ->
                              let idx =
                                Connection_limit.register_no_limit description
                              in
                              handle_connection client description idx
                          | _, _ -> Luv.Handle.close client ignore)))))

      let of_bound_fd ?read_buffer_size:_ fd =
        Luv_lwt.in_luv (fun return ->
            match Luv_unix.Os_fd.Fd.from_unix fd with
            | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
            | Ok fd -> (
                match Luv.Pipe.init () with
                | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
                | Ok pipe -> (
                    match Luv.File.open_osfhandle fd with
                    | Error err ->
                        Luv.Handle.close pipe (fun () ->
                            return (Error (`Msg (Luv.Error.strerror err))))
                    | Ok file -> (
                        match Luv.Pipe.open_ pipe file with
                        | Error err ->
                            Luv.Handle.close pipe (fun () ->
                                return (Error (`Msg (Luv.Error.strerror err))))
                        | Ok () -> (
                            match Luv.Pipe.getsockname pipe with
                            | Error err ->
                                Luv.Handle.close pipe (fun () ->
                                    return
                                      (Error (`Msg (Luv.Error.strerror err))))
                            | Ok path ->
                                let description = "unix:" ^ path in
                                let idx =
                                  Connection_limit.register_no_limit description
                                in
                                return (Ok (pipe, idx)))))))
        >>= function
        | Error (`Msg m) ->
            Log.warn (fun f -> f "%s" m);
            failwith m
        | Ok (fd, idx) ->
            Lwt.return
              { idx; fd; closed = false; disable_connection_tracking = false }

      let shutdown server =
        if not server.closed then (
          server.closed <- true;
          Luv_lwt.in_luv (fun return ->
              Connection_limit.deregister server.idx;
              Luv.Handle.close server.fd return))
        else Lwt.return_unit
    end
  end
end

module type ClientServer = sig
  include Sig.FLOW_CLIENT

  include Sig.FLOW_SERVER with type address := address and type flow := flow

  val get_test_address : unit -> address
end

module TestServer (F : ClientServer) = struct
  let with_server address f =
    F.bind address >>= fun server ->
    Lwt.finalize (fun () -> f server) (fun () -> F.shutdown server)

  let with_flow flow f = Lwt.finalize f (fun () -> F.close flow)

  let one_connection () =
    Luv_lwt.run
      (let address = F.get_test_address () in
       with_server address (fun server ->
           let connected = Lwt_mvar.create_empty () in
           F.listen server (fun flow ->
               Lwt_mvar.put connected () >>= fun () -> F.close flow);
           F.connect address >>= function
           | Error (`Msg m) -> Lwt.fail_with m
           | Ok flow ->
               with_flow flow (fun () ->
                   Lwt_mvar.take connected >>= fun () -> Lwt.return_unit)))

  let stream_data () =
    Luv_lwt.run
      (let address = F.get_test_address () in
       with_server address (fun server ->
           let received = Lwt_mvar.create_empty () in
           F.listen server (fun flow ->
               with_flow flow (fun () ->
                   let sha = Sha1.init () in
                   let rec loop () =
                     F.read flow >>= function
                     | Error _ -> Lwt.return_unit
                     | Ok `Eof -> Lwt.return_unit
                     | Ok (`Data buf) ->
                         let ba = Cstruct.to_bigarray buf in
                         Sha1.update_buffer sha ba;
                         loop ()
                   in
                   loop () >>= fun () ->
                   Lwt.return Sha1.(to_hex @@ finalize sha))
               >>= fun digest -> Lwt_mvar.put received digest);
           F.connect address >>= function
           | Error (`Msg m) -> Lwt.fail_with m
           | Ok flow ->
               with_flow flow (fun () ->
                   let buf = Cstruct.create 1048576 in
                   let sha = Sha1.init () in
                   let rec loop = function
                     | 0 -> Lwt.return_unit
                     | n -> (
                         let len = Random.int (Cstruct.len buf - 1) in
                         let subbuf = Cstruct.sub buf 0 len in
                         for i = 0 to Cstruct.len subbuf - 1 do
                           Cstruct.set_uint8 subbuf i (Random.int 256)
                         done;
                         let ba = Cstruct.to_bigarray subbuf in
                         Sha1.update_buffer sha ba;
                         F.writev flow [ subbuf ] >>= function
                         | Error _ -> Lwt.fail_with "write error"
                         | Ok () -> loop (n - 1))
                   in
                   loop 10 >>= fun () ->
                   Lwt.return Sha1.(to_hex @@ finalize sha))
               >>= fun sent_digest ->
               Lwt_mvar.take received >>= fun received_digest ->
               if received_digest <> sent_digest then
                 failwith
                   (Printf.sprintf "received digest (%s) <> sent digest (%s)"
                      received_digest sent_digest);
               Lwt.return_unit))
end

let%test_module "Sockets.Stream.Unix" =
  (module struct
    module Tests = TestServer (Sockets.Stream.Unix)

    let%test_unit "one connection" = Tests.one_connection ()

    let%test_unit "stream data" = Tests.stream_data ()
  end)

let%test_module "Sockets.Stream.TCP" =
  (module struct
    module Tests = TestServer (Sockets.Stream.Tcp)

    let%test_unit "one connection" = Tests.one_connection ()

    let%test_unit "stream data" = Tests.stream_data ()
  end)

module Files = struct
  let read_file path =
    (* Caller wants a string *)
    let buf = Buffer.create 4096 in
    let frag = Luv.Buffer.create 4096 in
    Luv_lwt.in_luv (fun return ->
        let rec loop h =
          Luv.File.read h [ frag ] (function
            | Ok n ->
                if n = Unsigned.Size_t.zero then
                  Luv.File.close h (function
                    | Error err ->
                        return (Error (`Msg (Luv.Error.strerror err)))
                    | Ok () -> return (Ok (Buffer.contents buf)))
                else (
                  Luv.Buffer.(
                    sub frag ~offset:0 ~length:(Unsigned.Size_t.to_int n)
                    |> to_bytes)
                  |> Buffer.add_bytes buf;
                  loop h)
            | Error err ->
                Luv.File.close h (function
                  | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
                  | Ok () -> return (Error (`Msg (Luv.Error.strerror err)))))
        in
        Luv.File.open_ path [ `RDONLY ] (function
          | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
          | Ok h -> loop h))

  let%test "read a file" =
    let expected = Buffer.create 8192 in
    for i = 0 to 1024 do
      Buffer.add_int64_be expected (Int64.of_int i)
    done;
    let filename = Filename.temp_file "vpnkit" "file" in
    let oc = open_out_bin filename in
    output_string oc (Buffer.contents expected);
    close_out oc;
    Luv_lwt.run
      ( read_file filename >>= fun result ->
        Sys.remove filename;
        match result with
        | Error (`Msg m) -> failwith m
        | Ok actual -> Lwt.return (Buffer.contents expected = actual) )

  type watch = { h : [ `FS_event ] Luv.Handle.t }

  let unwatch w =
    Luv_lwt.in_luv (fun return ->
        match Luv.FS_event.stop w.h with
        | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
        | Ok () -> return (Ok ())
    ) >>= function
    | Error (`Msg m) -> Lwt.fail_with m
    | Ok () -> Lwt.return_unit

  let watch_file path callback =
    Luv_lwt.in_luv (fun return ->
        match Luv.FS_event.init () with
        | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
        | Ok h ->
            Luv.FS_event.start h path (function
              | Ok _ -> Luv_lwt.in_lwt_async callback
              | Error err ->
                  Log.warn (fun f ->
                      f "watching %s: %s" path (Luv.Error.err_name err)));
            return (Ok { h }))

  let%test "watch a file" =
    let filename = Filename.temp_file "vpnkit" "file" in
    let oc = open_out_bin filename in
    Luv_lwt.run
      (let m = Lwt_mvar.create () in
       watch_file filename (fun () -> Lwt.async (fun () -> Lwt_mvar.put m ()))
       >>= function
       | Error (`Msg m) ->
           close_out oc;
           Sys.remove filename;
           failwith m
       | Ok w ->
           output_string oc "one";
           flush oc;
           Lwt_mvar.take m >>= fun () ->
           output_string oc "two";
           flush oc;
           Lwt_mvar.take m >>= fun () ->
           close_out oc;
           Sys.remove filename;
           unwatch w >>= fun () -> Lwt.return true)
end

module Time = struct
  type 'a io = 'a Lwt.t

  let sleep_ns ns =
    Luv_lwt.in_luv (fun return ->
      match Luv.Timer.init() with
      | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
      | Ok timer ->
        begin match
          Luv.Timer.start timer (Duration.to_ms ns) (fun () -> return (Ok ()))
        with
        | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
        | Ok () -> ()
        end
    ) >>= function
    | Error (`Msg m) -> Lwt.fail_with m
    | Ok () -> Lwt.return_unit

  let%test "Time.sleep_ns wakes up" =
    let start = Unix.gettimeofday () in
    Luv_lwt.run @@ sleep_ns @@ Duration.of_ms 100;
    let duration = Unix.gettimeofday () -. start in
    duration >= 0.1
end

module Dns = struct
  let getaddrinfo node family =
    Luv_lwt.in_luv (fun return ->
        Luv.DNS.getaddrinfo ~family ~node () (function
          | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
          | Ok x ->
              let ips =
                List.fold_left
                  (fun acc addr_info ->
                    match addr_info.Luv.DNS.Addr_info.family with
                    | `INET -> (
                        match
                          Luv.Sockaddr.to_string
                            addr_info.Luv.DNS.Addr_info.addr
                        with
                        | None -> acc
                        | Some ip -> (
                            match Ipaddr.of_string ip with
                            | Some ip -> ip :: acc
                            | None -> acc))
                    | _ -> acc)
                  [] x
              in
              return (Ok ips)))
    >>= function
    | Error (`Msg _) ->
        (* FIXME: error handling completely missing *)
        Lwt.return []
    | Ok ips -> Lwt.return ips

  let%test "getaddrinfo dave.recoil.org" =
    Luv_lwt.run
      (getaddrinfo "dave.recoil.org" `INET >>= fun ips -> Lwt.return (ips <> []))

  let localhost_local = Dns.Name.of_string "localhost.local"

  let resolve_getaddrinfo question =
    let open Dns.Packet in
    (match question with
    | { q_class = Q_IN; q_name; _ } when q_name = localhost_local ->
        Log.debug (fun f -> f "DNS lookup of localhost.local: return NXDomain");
        Lwt.return (q_name, [])
    | { q_class = Q_IN; q_type = Q_A; q_name; _ } ->
        getaddrinfo (Dns.Name.to_string q_name) `INET >>= fun ips ->
        Lwt.return (q_name, ips)
    | { q_class = Q_IN; q_type = Q_AAAA; q_name; _ } ->
        getaddrinfo (Dns.Name.to_string q_name) `INET6 >>= fun ips ->
        Lwt.return (q_name, ips)
    | _ -> Lwt.return (Dns.Name.of_string "", []))
    >>= function
    | _, [] -> Lwt.return []
    | q_name, ips ->
        let answers =
          List.map
            (function
              | Ipaddr.V4 v4 ->
                  {
                    name = q_name;
                    cls = RR_IN;
                    flush = false;
                    ttl = 0l;
                    rdata = A v4;
                  }
              | Ipaddr.V6 v6 ->
                  {
                    name = q_name;
                    cls = RR_IN;
                    flush = false;
                    ttl = 0l;
                    rdata = AAAA v6;
                  })
            ips
        in
        Lwt.return answers

  let resolve = resolve_getaddrinfo
end

module Main = struct
  let run = Luv_lwt.run

  let%test "Host.Main.Run has a working luv event loop" =
    run (Time.sleep_ns (Duration.of_ms 100));
    true

  let run_in_main = Lwt_preemptive.run_in_main

  let%test_unit "run_in_main" =
    let m = Lwt_mvar.create_empty () in
    let t =
      Thread.create
        (fun () -> run_in_main @@ fun () -> Lwt_mvar.put m "hello")
        ()
    in
    run
      (let open Lwt.Infix in
      Lwt_mvar.take m >>= fun x ->
      if x <> "hello" then
        failwith ("expected mvar to contain 'hello', got " ^ x);
      Lwt.return_unit);
    Thread.join t
end

module Fn = struct
  type ('request, 'response) t = 'request -> 'response

  let create f = f

  let destroy _ = ()

  let fn = Lwt_preemptive.detach

  let%test_unit "detach" =
    Main.run
      (let open Lwt.Infix in
      fn (fun () -> "hello") () >>= fun x ->
      if x <> "hello" then
        failwith ("expected thread to produce 'hello', got " ^ x);
      Lwt.return_unit)
end

let compact () =
  let start = Unix.gettimeofday () in
  Gc.compact ();
  let stats = Gc.stat () in
  let time = Unix.gettimeofday () -. start in

  Log.info (fun f ->
      f
        "Gc.compact took %.1f seconds. Heap has heap_words=%d live_words=%d \
         free_words=%d top_heap_words=%d stack_size=%d"
        time stats.Gc.heap_words stats.Gc.live_words stats.Gc.free_words
        stats.Gc.top_heap_words stats.Gc.stack_size)

let start_background_gc config =
  match config with
  | None -> Log.info (fun f -> f "No periodic Gc.compact enabled")
  | Some s ->
    begin match Luv.Timer.init () with
    | Error err -> Log.err (fun f -> f "Unable to configure periodic Gc.compact: %s" (Luv.Error.strerror err))
    | Ok timer ->
      begin match Luv.Timer.start timer (5 * 1000) ~repeat:(s * 1000) compact with
      | Error err -> Log.err (fun f -> f "Unable to start periodic Gc.compact: %s" (Luv.Error.strerror err))
      | Ok () -> ()
      end
    end

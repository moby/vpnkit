open Lwt.Infix

let src =
  let src = Logs.Src.create "Lwt_unix" ~doc:"Host interface based on Lwt_unix" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let default_read_buffer_size = 65536

let log_exception_continue description f =
  Lwt.catch
    (fun () -> f ())
    (fun e ->
       Log.err (fun f -> f "%s: caught %s" description (Printexc.to_string e));
       Lwt.return ()
    )

module Sockets = struct

let max_connections = ref None

let set_max_connections x = max_connections := x

let next_connection_idx =
  let idx = ref 0 in
  fun () ->
    let next = !idx in
    incr idx;
    next

exception Too_many_connections

let connection_table = Hashtbl.create 511
let connections =
  let connections =
    Vfs.Dir.of_list
      (fun () ->
        Vfs.ok (
          Hashtbl.fold
            (fun _ c acc -> Vfs.Inode.dir c Vfs.Dir.empty :: acc)
            connection_table []
        )
      ) in
  Vfs.Dir.of_list
    (fun () ->
      Vfs.ok [
        Vfs.Inode.dir "connections" connections
      ]
    )
let register_connection_no_limit description =
  let idx = next_connection_idx () in
  Hashtbl.replace connection_table idx description;
  idx
let register_connection =
  let last_error_log = ref 0. in
  fun description -> match !max_connections with
  | Some m when Hashtbl.length connection_table >= m ->
    let now = Unix.gettimeofday () in
    if (now -. !last_error_log) > 30. then begin
      (* Avoid hammering the logging system *)
      Log.err (fun f -> f "exceeded maximum number of forwarded connections (%d)" m);
      last_error_log := now;
    end;
    Lwt.fail Too_many_connections
  | _ ->
    let idx = register_connection_no_limit description in
    Lwt.return idx
let deregister_connection idx =
  Hashtbl.remove connection_table idx

let string_of_sockaddr = function
  | Lwt_unix.ADDR_INET(ip, port) -> Unix.string_of_inet_addr ip ^ ":" ^ (string_of_int port)
  | Lwt_unix.ADDR_UNIX path -> path

let unix_bind_one pf ty ip port =
  let protocol = match pf, ty with
    | Unix.PF_INET, Unix.SOCK_STREAM -> "tcp:"
    | Unix.PF_INET, Unix.SOCK_DGRAM  -> "udp:"
    | _, _ -> "unknown:" in
  let description = protocol ^ (Ipaddr.to_string ip) ^ ":" ^ (string_of_int port) in
  register_connection description
  >>= fun idx ->
  let addr = Lwt_unix.ADDR_INET(Unix.inet_addr_of_string @@ Ipaddr.to_string ip, port) in
  let fd = try Lwt_unix.socket pf ty 0 with e -> deregister_connection idx; raise e in
  Lwt.catch
    (fun () ->
      Lwt_unix.setsockopt fd Lwt_unix.SO_REUSEADDR true;
      Lwt_unix.bind fd addr;
      Lwt.return (idx, fd)
    ) (fun e ->
      Lwt_unix.close fd
      >>= fun () ->
      deregister_connection idx;
      Lwt.fail e
    )

let unix_bind ty (local_ip, local_port) =
  unix_bind_one Lwt_unix.PF_INET ty Ipaddr.(V4 local_ip) local_port
  >>= fun (idx, fd) ->
  let local_port = match local_port, Lwt_unix.getsockname fd with
    | 0, Unix.ADDR_INET(_, local_port) -> local_port
    | 0, _ -> assert false (* common only uses ADDR_INET *)
    | _ -> local_port in
  (* On some systems localhost will resolve to ::1 first and this can
     cause performance problems (particularly on Windows). Perform a
     best-effort bind to the ::1 address. *)
  Lwt.catch
    (fun () ->
      if Ipaddr.V4.compare local_ip Ipaddr.V4.localhost = 0
      || Ipaddr.V4.compare local_ip Ipaddr.V4.any = 0
      then begin
        Log.info (fun f -> f "attempting a best-effort bind of ::1:%d" local_port);
        unix_bind_one Lwt_unix.PF_INET6 ty Ipaddr.(V6 V6.localhost) local_port
        >>= fun (idx, fd) ->
        Lwt.return [ idx, fd ]
      end else begin
        Lwt.return []
      end
    ) (fun e ->
      Log.info (fun f -> f "ignoring failed bind to ::1:%d (%s)" local_port (Printexc.to_string e));
      Lwt.return []
    )
  >>= fun extra ->
  Lwt.return ((idx, fd) :: extra)

module Datagram = struct
  type reply = Cstruct.t -> unit Lwt.t

  type flow = {
    idx: int;
    description: string;
    fd: Lwt_unix.file_descr;
    mutable last_use: float;
    (* For protocols like NTP the source port keeps changing, so we send
       replies to the last source port we saw. *)
    mutable reply: reply;
  }

  (* FIXME: deduplicate some of the common code here with Host_uwt *)

  (* Look up by src * src_port *)
  let table = Hashtbl.create 7

  let get_nat_table_size () = Hashtbl.length table

  let _ =
    let rec loop () =
      Lwt_unix.sleep 60.
      >>= fun () ->
      let snapshot = Hashtbl.copy table in
      let now = Unix.gettimeofday () in
      Hashtbl.iter (fun k flow ->
          if now -. flow.last_use > 60. then begin
            Log.debug (fun f -> f "Socket.Datagram %s: expiring UDP NAT rule" flow.description);
            Lwt.async (fun () ->
              Lwt.catch (fun () ->
                Lwt_unix.close flow.fd
                >>= fun () ->
                deregister_connection flow.idx;
                Lwt.return_unit
              ) (fun e ->
                Log.err (fun f -> f "Socket.Datagram %s: caught %s while closing UDP socket" flow.description (Printexc.to_string e));
                Lwt.return ()
              )
            );
            Hashtbl.remove table k
          end
        ) snapshot;
      loop () in
    loop ()

  let input ?userdesc ~oneshot ~reply ~src:(src, src_port) ~dst:(dst, dst_port) ~payload () =
    let remote_sockaddr = Unix.ADDR_INET(Unix.inet_addr_of_string @@ Ipaddr.to_string dst, dst_port) in
    (if Hashtbl.mem table (src, src_port) then begin
        Lwt.return (Some (Hashtbl.find table (src, src_port)))
      end else begin
       let userdesc = match userdesc with
         | None -> ""
         | Some x -> String.concat "" [ " ("; x; ")" ] in
       let description = String.concat "" [ Ipaddr.to_string src; ":"; string_of_int src_port; "-"; Ipaddr.to_string dst; ":"; string_of_int dst_port; userdesc ] in
       if Ipaddr.compare dst Ipaddr.(V4 V4.broadcast) = 0 then begin
         Log.debug (fun f -> f "Socket.Datagram.input %s: ignoring broadcast packet" description);
         Lwt.return None
       end else begin
         Log.debug (fun f -> f "Socket.Datagram.input %s: creating UDP NAT rule" description);
         register_connection description
         >>= fun idx ->
         let fd = try Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_DGRAM 0 with e -> deregister_connection idx; raise e in
         (try Lwt_unix.bind fd (Lwt_unix.ADDR_INET(Unix.inet_addr_any, 0)) with _ -> ());
         let last_use = Unix.gettimeofday () in
         let flow = { idx; description; fd; last_use; reply} in
         Hashtbl.replace table (src, src_port) flow;
         (* Start a listener *)
         let buffer = Cstruct.create Constants.max_udp_length in
         let bytes = Bytes.make Constants.max_udp_length '\000' in
         let rec loop () =
           Lwt.catch
             (fun () ->
                (* Lwt on Win32 doesn't support Lwt_bytes.recvfrom *)
                Lwt_unix.recvfrom fd bytes 0 (String.length bytes) []
                >>= fun (n, _) ->
                Cstruct.blit_from_string bytes 0 buffer 0 n;
                let response = Cstruct.sub buffer 0 n in
                ( if oneshot then begin
                    Hashtbl.remove table (src, src_port);
                    Lwt_unix.close fd
                  end else Lwt.return_unit )
                >>= fun () ->
                flow.reply response
                >>= fun () ->
                Lwt.return (not oneshot)
             ) (function
                 | Unix.Unix_error(Unix.EBADF, _, _) ->
                   (* fd has been closed by the GC *)
                   Log.debug (fun f -> f "Socket.Datagram.input %s: shutting down listening thread" description);
                   Lwt.return false
                 | e ->
                   Log.err (fun f -> f "Socket.Datagram.input %s: caught unexpected exception %s" description (Printexc.to_string e));
                   Lwt.return false
               )
           >>= function
           | false -> Lwt.return ()
           | true -> loop () in
         Lwt.async loop;
         Lwt.return (Some flow)
       end
     end) >>= function
    | None -> Lwt.return ()
    | Some flow ->
      flow.reply <- reply;
      Lwt.catch
        (fun () ->
           (* Lwt on Win32 doesn't support Lwt_bytes.sendto *)
           let payload_string = Cstruct.to_string payload in
           Lwt_unix.sendto flow.fd payload_string 0 (String.length payload_string) [] remote_sockaddr
           >>= fun n ->
           if n <> payload.Cstruct.len
           then Log.err (fun f -> f "Socket.Datagram.input %s: Lwt_bytes.send short: expected %d got %d" flow.description payload.Cstruct.len n);
           flow.last_use <- Unix.gettimeofday ();
           Lwt.return ()
        ) (fun e ->
            Log.err (fun f -> f "Socket.Datagram.input %s: Lwt_bytes.send caught %s" flow.description (Printexc.to_string e));
            Lwt.return ()
          )

  type address = Ipaddr.t * int

  module Udp = struct

    type server = {
      idx: int;
      fd: Lwt_unix.file_descr;
      mutable closed: bool;
    }

    let make ~idx fd = { idx; fd; closed = false }

    let bind (ip, port) =
      unix_bind_one Lwt_unix.PF_INET Lwt_unix.SOCK_DGRAM ip port
      >>= fun (idx, fd) ->
      Lwt.return (make ~idx fd)

    let of_bound_fd fd =
      let description = match Unix.getsockname fd with
        | Lwt_unix.ADDR_INET(iaddr, port) ->
          "udp:" ^ (Unix.string_of_inet_addr iaddr) ^ ":" ^ (string_of_int port)
        | _ ->
          "unknown:" in
      let idx = register_connection_no_limit description in
      make ~idx (Lwt_unix.of_unix_file_descr fd)

    let getsockname { fd; _ } =
      match Lwt_unix.getsockname fd with
      | Lwt_unix.ADDR_INET(iaddr, port) ->
        Ipaddr.of_string_exn (Unix.string_of_inet_addr iaddr), port
      | _ -> invalid_arg "Tcp.getsockname passed a non-TCP socket"

    let shutdown server =
      if not server.closed then begin
        server.closed <- true;
        Lwt_unix.close server.fd
        >>= fun () ->
        deregister_connection server.idx;
        Lwt.return_unit
      end else Lwt.return_unit

    let recvfrom server buf =
      (* Lwt on Win32 doesn't support Lwt_bytes.sendto *)
      let str = Bytes.create (Cstruct.len buf) in
      Lwt_unix.recvfrom server.fd str 0 (String.length str) []
      >>= fun (len, sockaddr) ->
      Cstruct.blit_from_string str 0 buf 0 len;
      let address = match sockaddr with
        | Lwt_unix.ADDR_INET(ip, port) ->
          Ipaddr.of_string_exn @@ Unix.string_of_inet_addr ip, port
        | _ ->
          invalid_arg "recvfrom returned wrong sockaddr type" in
      Lwt.return (len, address)

    let sendto server (ip, port) buf =
      (* Lwt on Win32 doesn't support Lwt_bytes.sendto *)
      let len = Cstruct.len buf in
      let str = Bytes.create len in
      Cstruct.blit_to_bytes buf 0 str 0 len;
      let sockaddr = Lwt_unix.ADDR_INET(Unix.inet_addr_of_string @@ Ipaddr.to_string ip, port) in
      Lwt_unix.sendto server.fd str 0 len [] sockaddr
      >>= fun _ ->
      Lwt.return_unit
  end

end

module Stream = struct

  (* Using Lwt_unix we share an implementation across various transport types *)
  module Fd = struct
    type flow = {
      idx: int;
      description: string;
      fd: Lwt_unix.file_descr;
      read_buffer_size: int;
      mutable read_buffer: Cstruct.t;
      mutable closed: bool;
    }

    type error = [
      | `Msg of string
    ]

    let error_message = function
      | `Msg x -> x

    let errorf fmt = Printf.ksprintf (fun s -> Lwt.return (`Error (`Msg s))) fmt

    let of_fd ~idx ?(read_buffer_size = default_read_buffer_size) ~description fd =
      let read_buffer = Cstruct.create read_buffer_size in
      let closed = false in
      { idx; description; fd; read_buffer; read_buffer_size; closed }

    let shutdown_read { description; fd; closed; _ } =
      try
        if not closed then Lwt_unix.shutdown fd Unix.SHUTDOWN_RECEIVE;
        Lwt.return ()
      with
      | Unix.Unix_error(Unix.ENOTCONN, _, _) -> Lwt.return ()
      | e ->
        Log.err (fun f -> f "Socket.TCPV4.shutdown_read %s: caught %s returning Eof" description (Printexc.to_string e));
        Lwt.return ()

    let shutdown_write { description; fd; closed; _ } =
      try
        if not closed then Lwt_unix.shutdown fd Unix.SHUTDOWN_SEND;
        Lwt.return ()
      with
      | Unix.Unix_error(Unix.ENOTCONN, _, _) -> Lwt.return ()
      | e ->
        Log.err (fun f -> f "Socket.TCPV4.shutdown_write %s: caught %s returning Eof" description (Printexc.to_string e));
        Lwt.return ()

    let read t =
      if t.closed then Lwt.return `Eof
      else begin
        if Cstruct.len t.read_buffer = 0 then t.read_buffer <- Cstruct.create t.read_buffer_size;
        Lwt.catch
          (fun () ->
             Lwt_bytes.read t.fd t.read_buffer.Cstruct.buffer t.read_buffer.Cstruct.off t.read_buffer.Cstruct.len
             >>= function
             | 0 -> Lwt.return `Eof
             | n ->
               let results = Cstruct.sub t.read_buffer 0 n in
               t.read_buffer <- Cstruct.shift t.read_buffer n;
               Lwt.return (`Ok results)
          ) (fun e ->
              Log.err (fun f -> f "Socket.TCPV4.read %s: caught %s returning Eof" t.description (Printexc.to_string e));
              Lwt.return `Eof
            )
      end

    let read_into t buffer =
      if t.closed then Lwt.return `Eof
      else
        Lwt.catch
          (fun () ->
            Lwt_cstruct.(complete (read t.fd) buffer)
            >>= fun () ->
            Lwt.return (`Ok ())
          ) (fun _e -> Lwt.return `Eof)

    let write t buf =
      if t.closed then Lwt.return `Eof
      else
      Lwt.catch
        (fun () ->
           Lwt_cstruct.(complete (write t.fd) buf)
           >>= fun () ->
           Lwt.return (`Ok ())
        ) (fun e ->
            Log.err (fun f -> f "Socket.TCPV4.write %s: caught %s returning Eof" t.description (Printexc.to_string e));
            Lwt.return `Eof
          )

    let writev t bufs =
      Lwt.catch
        (fun () ->
           let rec loop = function
             | [] -> Lwt.return (`Ok ())
             | buf :: bufs ->
               if t.closed then Lwt.return `Eof
               else
                 Lwt_cstruct.(complete (write t.fd) buf)
                 >>= fun () ->
                 loop bufs in
           loop bufs
        ) (fun e ->
            Log.err (fun f -> f "Socket.TCPV4.writev %s: caught %s returning Eof" t.description (Printexc.to_string e));
            Lwt.return `Eof
          )

    let close t =
      if not t.closed then begin
        t.closed <- true;
        Lwt_unix.close t.fd
        >>= fun () ->
        deregister_connection t.idx;
        Lwt.return_unit
      end else Lwt.return ()

    let connect description ?(read_buffer_size = default_read_buffer_size) sock_domain sock_ty sockaddr =
      register_connection description
      >>= fun idx ->
      let fd = Lwt_unix.socket sock_domain sock_ty 0 in
      Lwt.catch
        (fun () ->
           Log.debug (fun f -> f "%s: connecting" description);
           Lwt_unix.connect fd sockaddr
           >>= fun () ->
           Lwt.return (`Ok (of_fd ~idx ~read_buffer_size ~description fd))
        )
        (fun e ->
           Lwt_unix.close fd
           >>= fun () ->
           deregister_connection idx;
           errorf "%s: Lwt_unix.connect: caught %s" description (Printexc.to_string e)
        )

    type server = {
      mutable listening_fds: (int * Lwt_unix.file_descr) list;
      read_buffer_size: int;
      path: string; (* only for Win32 *)
      mutable closed: bool;
    }

    let make ?(read_buffer_size = default_read_buffer_size) ?(path="") listening_fds =
      { listening_fds; read_buffer_size; path; closed = false }

    let shutdown server =
      let fds = server.listening_fds in
      server.listening_fds <- [];
      server.closed <- true;
      Lwt_list.iter_s
        (fun (idx, fd) ->
          Lwt_unix.close fd
          >>= fun () ->
          deregister_connection idx;
          Lwt.return_unit
        ) fds

    let of_bound_fd ?(read_buffer_size = default_read_buffer_size) fd =
      let description = match Unix.getsockname fd with
        | Lwt_unix.ADDR_INET(iaddr, port) ->
          "udp:" ^ (Unix.string_of_inet_addr iaddr) ^ ":" ^ (string_of_int port)
        | _ ->
          "unknown:" in
      let idx = register_connection_no_limit description in
      make ~read_buffer_size [ idx, Lwt_unix.of_unix_file_descr fd ]

    let listen server cb =
      let rec loop fd =
        Lwt_unix.accept fd
        >>= fun (client, sockaddr) ->
        let read_buffer_size = server.read_buffer_size in
        let description = string_of_sockaddr sockaddr in

        Lwt.async
         (fun () ->
           Lwt.catch
             (fun () ->
               register_connection description
               >>= fun idx ->
               Lwt.return (Some (of_fd ~idx ~read_buffer_size ~description client))
             ) (fun _e ->
               Lwt_unix.close client
               >>= fun () ->
               Lwt.return_none
             )
           >>= function
           | None -> Lwt.return_unit
           | Some flow ->
            Lwt.finalize
              (fun () ->
                log_exception_continue "Socket.Stream"
                  (fun () ->
                    cb flow
                  )
              ) (fun () -> close flow)
        );
        loop fd in
      List.iter
        (fun (_idx, fd) ->
          Lwt.async
            (fun () ->
              log_exception_continue "Socket.Stream"
                (fun () ->
                  Lwt.finalize
                    (fun () ->
                      Lwt_unix.listen fd 32;
                      loop fd
                    ) (fun () ->
                      shutdown server
                    )
                )
            )
        ) server.listening_fds

    (* FLOW boilerplate *)
    type 'a io = 'a Lwt.t
    type buffer = Cstruct.t
  end

  module Tcp = struct
    include Fd

    type address = Ipaddr.V4.t * int

    let connect ?read_buffer_size (ip, port) =
      let description = Ipaddr.V4.to_string ip ^ ":" ^ (string_of_int port) in
      let sockaddr = Unix.ADDR_INET (Unix.inet_addr_of_string @@ Ipaddr.V4.to_string ip, port) in
      connect description ?read_buffer_size Lwt_unix.PF_INET Lwt_unix.SOCK_STREAM sockaddr

    let bind (ip, port) =
      unix_bind Lwt_unix.SOCK_STREAM (ip, port)
      >>= fun fds ->
      Lwt.return (make fds)

    let getsockname server = match server.listening_fds with
      | [] -> failwith "Tcp.getsockname: socket is closed"
      | (_idx, fd) :: _ ->
        match Lwt_unix.getsockname fd with
        | Lwt_unix.ADDR_INET(iaddr, port) ->
          Ipaddr.V4.of_string_exn (Unix.string_of_inet_addr iaddr), port
        | _ -> invalid_arg "Tcp.getsockname passed a non-TCP socket"
  end

  module Unix = struct
    include Fd

    type address = string

    let is_win32 = Sys.os_type = "win32"

    let connect ?read_buffer_size path =
      let description = "unix:" ^ path in
      if is_win32 then begin
        register_connection description
        >>= fun idx ->
        Named_pipe_lwt.Client.openpipe path
        >>= fun p ->
        let fd = Named_pipe_lwt.Client.to_fd p in
        Lwt.return (`Ok (of_fd ~idx ?read_buffer_size ~description fd))
      end else begin
        let sockaddr = Unix.ADDR_UNIX path in
        connect description ?read_buffer_size Lwt_unix.PF_UNIX Lwt_unix.SOCK_STREAM sockaddr
      end

    let bind path =
      let description = "unix:" ^ path in
      if is_win32
      then Lwt.return (make ~path [])
      else
        Lwt.catch
          (fun () ->
            Lwt_unix.unlink path
          ) (function
            | Unix.Unix_error(Unix.ENOENT, _, _) -> Lwt.return ()
            | e -> Lwt.fail e)
        >>= fun () ->
        register_connection description
        >>= fun idx ->
        let s = Lwt_unix.socket Lwt_unix.PF_UNIX Lwt_unix.SOCK_STREAM 0 in
        Lwt.catch
          (fun () ->
            Lwt_unix.bind s (Lwt_unix.ADDR_UNIX path);
            Lwt.return (make ~path [ idx, s ])
          ) (fun e ->
            Lwt_unix.close s
            >>= fun () ->
            deregister_connection idx;
            Lwt.fail e
          )

      let listen server cb =
        if not is_win32
        then listen server cb
        else
          let rec loop () =
            let open Lwt.Infix in
            if server.closed
            then Lwt.return_unit
            else begin
              let p = Named_pipe_lwt.Server.create server.path in
              Named_pipe_lwt.Server.connect p
              >>= function
              | false ->
                Log.err (fun f -> f "Named-pipe connection failed on %s" server.path);
                Lwt.return ()
              | true ->
                let description = "named-pipe:" ^ server.path in
                let read_buffer_size = server.read_buffer_size in
                let fd = Named_pipe_lwt.Server.to_fd p in
                Lwt.catch
                  (fun () ->
                    register_connection description
                    >>= fun idx ->
                    Lwt.return (Some (of_fd ~idx ~read_buffer_size ~description fd))
                  ) (fun _e ->
                    Lwt_unix.close fd
                    >>= fun () ->
                    Lwt.return None
                  )
                 >>= function
                 | None -> Lwt.return_unit
                 | Some flow ->
                  Lwt.async
                    (fun () ->
                      Lwt.finalize
                        (fun () ->
                          log_exception_continue "Socket.Stream.Unix"
                            (fun () ->
                              cb flow
                            )
                        ) (fun () -> close flow)
                    );
                loop ()
            end in
        Lwt.async
          (fun () ->
            log_exception_continue "Socket.Stream.Unix"
              (fun () -> loop ())
          )

    let getsockname server = server.path

    let unsafe_get_raw_fd t =
      (* By default Lwt sets fds to non-blocking mode. Reverse this to avoid
         surprising the caller. *)
      Lwt_unix.set_blocking ~set_flags:true t.fd true;
      Lwt_unix.unix_file_descr t.fd

  end

end
end

module Files = struct
let read_file path =
  let open Lwt.Infix in
  Lwt.catch
    (fun () ->
      Lwt_unix.openfile path [ Lwt_unix.O_RDONLY ] 0
      >>= fun fd ->
      let buffer = Buffer.create 128 in
      let frag = Bytes.make 1024 ' ' in
      Lwt.finalize
        (fun () ->
          let rec loop () =
            Lwt_unix.read fd frag 0 (Bytes.length frag)
            >>= function
            | 0 ->
              Lwt.return (`Ok (Buffer.contents buffer))
            | n ->
              Buffer.add_substring buffer frag 0 n;
              loop () in
          loop ()
        ) (fun () ->
          Lwt_unix.close fd
        )
    ) (fun e ->
      Lwt.return (`Error (`Msg (Printf.sprintf "reading %s: %s" path (Printexc.to_string e))))
    )

  type watch = unit Lwt.t

  let watch_file path callback =
    (* Poll the file every 5s seconds *)
    let start () =
      Lwt_unix.stat path
      >>= function { Lwt_unix.st_mtime; _ } ->
      callback ();
      let rec poll st_mtime' =
        Lwt_unix.stat path
        >>= function { Lwt_unix.st_mtime; _ } ->
        if st_mtime' <> st_mtime then callback ();
        Lwt_unix.sleep 5.
        >>= fun () ->
        poll st_mtime in
      poll st_mtime in
    (* On failure, wait another 5s and try again *)
    let rec loop () =
      Lwt.catch start
        (fun e ->
          Log.err (fun f -> f "While watching %s: %s" path (Printexc.to_string e));
          Lwt.return ()
        )
      >>= fun () ->
      Lwt_unix.sleep 5.
      >>= fun () ->
      loop () in
    let handle = loop () in
    `Ok handle

  let unwatch = Lwt.cancel
end

module Time = struct
type 'a io = 'a Lwt.t

let sleep = Lwt_unix.sleep
end

module Main = struct
  let run = Lwt_main.run
  let run_in_main = Lwt_preemptive.run_in_main
end

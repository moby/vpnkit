open Lwt.Infix

let src =
  let src =
    Logs.Src.create "Lwt_unix" ~doc:"Host interface based on Lwt_unix"
  in
  Logs.Src.set_level src (Some Logs.Info);
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

module Common = struct
  (** FLOW boilerplate *)

  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type error = [`Msg of string]
  type write_error = [Mirage_flow.write_error | error]
  let pp_error ppf (`Msg x) = Fmt.string ppf x

  let pp_write_error ppf = function
  | #Mirage_flow.write_error as e -> Mirage_flow.pp_write_error ppf e
  | #error as e                   -> pp_error ppf e

  let errorf fmt = Fmt.kstrf (fun s -> Lwt_result.fail (`Msg s)) fmt
end

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

  let get_num_connections () = Hashtbl.length connection_table

  let connections () =
    let xs = Hashtbl.fold (fun _ c acc -> c :: acc) connection_table [] in
    Vfs.File.ro_of_string (String.concat "\n" xs)

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
        Log.err (fun f ->
            f "exceeded maximum number of forwarded connections (%d)" m);
        last_error_log := now;
      end;
      Lwt.fail Too_many_connections
    | _ ->
      let idx = register_connection_no_limit description in
      Lwt.return idx

  let deregister_connection idx =
    Hashtbl.remove connection_table idx

  let address_of_sockaddr = function
  | Lwt_unix .ADDR_INET(ip, port) ->
    (try Some (Ipaddr.of_string_exn @@ Unix.string_of_inet_addr ip, port)
    with _ -> None)
  | _ -> None

  let string_of_sockaddr = function
  | Lwt_unix.ADDR_INET(ip, port) ->
    Fmt.strf "%s:%d" (Unix.string_of_inet_addr ip) port
  | Lwt_unix.ADDR_UNIX path -> path

  let string_of_address (dst, dst_port) =
    Fmt.strf "%s:%d" (Ipaddr.to_string dst) dst_port

  let sockaddr_of_address (dst, dst_port) =
    Unix.ADDR_INET(Unix.inet_addr_of_string @@ Ipaddr.to_string dst, dst_port)

  let unix_bind_one ?(description="") pf ty ip port =
    let protocol = match pf, ty with
    | (Unix.PF_INET | Unix.PF_INET6), Unix.SOCK_STREAM -> "tcp:"
    | (Unix.PF_INET | Unix.PF_INET6), Unix.SOCK_DGRAM  -> "udp:"
    | _, _ -> "unknown:" in
    let description =
      Fmt.strf "%s%a:%d %s" protocol Ipaddr.pp_hum ip port description
    in
    register_connection description >>= fun idx ->
    let addr =
      Lwt_unix.ADDR_INET(Unix.inet_addr_of_string @@ Ipaddr.to_string ip, port)
    in
    let fd =
      try Lwt_unix.socket pf ty 0
      with e -> deregister_connection idx; raise e
    in
    Lwt.catch (fun () ->
        Lwt_unix.setsockopt fd Lwt_unix.SO_REUSEADDR true;
        Lwt_unix.bind fd addr >|= fun () ->
        idx, fd
      ) (fun e ->
        Lwt_unix.close fd
        >>= fun () ->
        deregister_connection idx;
        Lwt.fail e
      )

  let unix_bind ?description ty (local_ip, local_port) =
    let pf = match local_ip with
    | Ipaddr.V4 _ -> Lwt_unix.PF_INET
    | Ipaddr.V6 _ -> Lwt_unix.PF_INET6 in
    unix_bind_one ?description pf ty local_ip local_port
    >>= fun (idx, fd) ->
    let local_port = match local_port, Lwt_unix.getsockname fd with
    | 0, Unix.ADDR_INET(_, local_port) -> local_port
    | 0, _ -> assert false (* common only uses ADDR_INET *)
    | _ -> local_port in
    (* On some systems localhost will resolve to ::1 first and this
       can cause performance problems (particularly on
       Windows). Perform a best-effort bind to the ::1 address. *)
    Lwt.catch (fun () ->
        if Ipaddr.compare local_ip (Ipaddr.V4 Ipaddr.V4.localhost) = 0
        || Ipaddr.compare local_ip (Ipaddr.V4 Ipaddr.V4.any) = 0
        then begin
          Log.info (fun f ->
              f "attempting a best-effort bind of ::1:%d" local_port);
          unix_bind_one
            ?description Lwt_unix.PF_INET6 ty Ipaddr.(V6 V6.localhost) local_port
          >|= fun (idx, fd) ->
          [ idx, fd ]
        end else
          Lwt.return []
      ) (fun e ->
        Log.info (fun f ->
            f "ignoring failed bind to ::1:%d (%a)" local_port Fmt.exn e);
        Lwt.return []
      )
    >|= fun extra ->
    (idx, fd) :: extra

  module Datagram = struct
    type address = Ipaddr.t * int

    module Udp = struct
      include Common

      type flow = {
        mutable idx: int option;
        description: string;
        mutable fd: Lwt_unix.file_descr option;
        read_buffer_size: int;
        mutable already_read: Cstruct.t option;
        sockaddr: Unix.sockaddr;
        address: address;
      }

      type address = Ipaddr.t * int

      let string_of_flow t = Fmt.strf "udp -> %s" (string_of_address t.address)

      let of_fd ?idx ~description ?(read_buffer_size = Constants.max_udp_length)
          ?(already_read = None) sockaddr address fd =
        { idx; description; fd = Some fd; read_buffer_size; already_read;
          sockaddr; address }

      let connect ?read_buffer_size address =
        let description = "udp:" ^ string_of_address address in
        register_connection description
        >>= fun idx ->
        let pf, addr = match fst address with
        | Ipaddr.V4 _ -> Lwt_unix.PF_INET, Unix.inet_addr_any
        | Ipaddr.V6 _ -> Lwt_unix.PF_INET6, Unix.inet6_addr_any in
        let fd = Lwt_unix.socket pf Lwt_unix.SOCK_DGRAM 0 in
        (* Win32 requires all sockets to be bound however macOS and
           Linux don't *)
        Lwt.catch (fun () ->
            Lwt_unix.bind fd (Lwt_unix.ADDR_INET(addr, 0))
          ) (fun _ -> Lwt.return_unit)
        >|= fun () ->
        let sockaddr = sockaddr_of_address address in
        Ok (of_fd ~idx ~description ?read_buffer_size sockaddr address fd)

      let read t = match t.fd, t.already_read with
      | None, _ -> Lwt.return (Ok `Eof)
      | Some _, Some data when Cstruct.len data > 0 ->
        t.already_read <- Some (Cstruct.sub data 0 0); (* next read is `Eof *)
        Lwt.return (Ok (`Data data))
      | Some _, Some _ ->
        Lwt.return (Ok `Eof)
      | Some fd, None ->
        let buffer = Cstruct.create t.read_buffer_size in
        let bytes = Bytes.make t.read_buffer_size '\000' in
        Lwt.catch (fun () ->
            (* Lwt on Win32 doesn't support Lwt_bytes.recvfrom *)
            Lwt_unix.recvfrom fd bytes 0 (Bytes.length bytes) []
            >>= fun (n, _) ->
            Cstruct.blit_from_bytes bytes 0 buffer 0 n;
            let response = Cstruct.sub buffer 0 n in
            Lwt.return (Ok (`Data response))
          ) (fun e ->
            Log.err (fun f ->
                f "%s: recvfrom caught %a returning Eof" (string_of_flow t)
                  Fmt.exn e);
            Lwt.return (Ok `Eof)
          )

      let write t buf = match t.fd with
      | None -> Lwt.return (Error `Closed)
      | Some fd ->
        Lwt.catch (fun () ->
            (* Lwt on Win32 doesn't support Lwt_bytes.sendto *)
            let bytes = Bytes.make (Cstruct.len buf) '\000' in
            Cstruct.blit_to_bytes buf 0 bytes 0 (Cstruct.len buf);
            Lwt_unix.sendto fd bytes 0 (Bytes.length bytes) [] t.sockaddr
            >|= fun _n ->
            Ok ()
          ) (fun e ->
            Log.err (fun f ->
                f "%s: sendto caught %a returning Eof" (string_of_flow t)
                  Fmt.exn e);
            Lwt.return (Error `Closed)
          )

      let writev t bufs = write t (Cstruct.concat bufs)

      let close t = match t.fd with
      | None -> Lwt.return_unit
      | Some fd ->
        t.fd <- None;
        Log.debug (fun f -> f "%s: close" (string_of_flow t));
        (match t.idx with Some idx -> deregister_connection idx | None -> ());
        Lwt_unix.close fd

      let shutdown_read _t = Lwt.return_unit
      let shutdown_write _t = Lwt.return_unit

      type server = {
        idx: int;
        fd: Lwt_unix.file_descr;
        mutable closed: bool;
        mutable disable_connection_tracking: bool;
      }

      let make ~idx fd =
        { idx; fd; closed = false; disable_connection_tracking = false }

      let disable_connection_tracking server =
        server.disable_connection_tracking <- true

      let bind ?description (ip, port) =
        let pf = match ip with
        | Ipaddr.V4 _ -> Lwt_unix.PF_INET
        | Ipaddr.V6 _ -> Lwt_unix.PF_INET6 in
        unix_bind_one ?description pf Lwt_unix.SOCK_DGRAM ip port
        >|= fun (idx, fd) ->
        make ~idx fd

      let of_bound_fd ?read_buffer_size:_ fd =
        let description = match Unix.getsockname fd with
        | Lwt_unix.ADDR_INET(iaddr, port) ->
          Fmt.strf "udp:%s:%d"  (Unix.string_of_inet_addr iaddr) port
        | _ -> "unknown:"
        in
        let idx = register_connection_no_limit description in
        make ~idx (Lwt_unix.of_unix_file_descr fd)

      let getsockname { fd; _ } =
        match Lwt_unix.getsockname fd with
        | Lwt_unix.ADDR_INET(iaddr, port) ->
          Ipaddr.of_string_exn (Unix.string_of_inet_addr iaddr), port
        | _ -> invalid_arg "Udp.getsockname passed a non-INET socket"

      let shutdown server =
        if not server.closed then begin
          server.closed <- true;
          Lwt_unix.close server.fd >|= fun () ->
          deregister_connection server.idx
        end else
          Lwt.return_unit

      let listen t flow_cb =
        let bytes = Bytes.make Constants.max_udp_length '\000' in
        let rec loop () =
          Lwt.catch (fun () ->
              (* Lwt on Win32 doesn't support Lwt_bytes.recvfrom *)
              Lwt_unix.recvfrom t.fd bytes 0 (Bytes.length bytes) []
              >>= fun (n, sockaddr) ->
              (* Allocate a fresh buffer because the packet will be processed
                 in a background thread *)
              let data = Cstruct.create n in
              Cstruct.blit_from_bytes bytes 0 data 0 n;
              (* construct a flow with this buffer available for reading *)
              ( match address_of_sockaddr sockaddr with
              | Some address -> Lwt.return address
              | None -> Lwt.fail_with "failed to discover incoming socket address"
              ) >>= fun address ->
              (* No new fd so no new idx *)
              let description = Fmt.strf "udp:%s" (string_of_address address) in
              let flow =
                of_fd ~description ~read_buffer_size:0 ~already_read:(Some data)
                  sockaddr address t.fd
              in
              Lwt.async (fun () ->
                  Lwt.catch
                    (fun () -> flow_cb flow)
                    (fun e ->
                       Log.info (fun f ->
                           f "Udp.listen callback caught: %a" Fmt.exn e);
                       Lwt.return_unit
                    ));
              Lwt.return true
            ) (fun e ->
              Log.err (fun f ->
                  f "Udp.listen caught %a shutting down server" Fmt.exn e);
              Lwt.return false
            )
          >>= function
          | false -> Lwt.return_unit
          | true -> loop ()
        in
        Lwt.async loop

      let recvfrom server buf =
        (* Lwt on Win32 doesn't support Lwt_bytes.sendto *)
        let str = Bytes.create (Cstruct.len buf) in
        Lwt_unix.recvfrom server.fd str 0 (String.length str) []
        >|= fun (len, sockaddr) ->
        Cstruct.blit_from_string str 0 buf 0 len;
        let address = match sockaddr with
        | Lwt_unix.ADDR_INET(ip, port) ->
          Ipaddr.of_string_exn @@ Unix.string_of_inet_addr ip, port
        | _ ->
          invalid_arg "recvfrom returned wrong sockaddr type"
        in
        len, address

      let sendto server (ip, port) buf =
        (* Lwt on Win32 doesn't support Lwt_bytes.sendto *)
        let len = Cstruct.len buf in
        let str = Bytes.create len in
        Cstruct.blit_to_bytes buf 0 str 0 len;
        let sockaddr =
          Lwt_unix.ADDR_INET
            (Unix.inet_addr_of_string @@ Ipaddr.to_string ip, port)
        in
        Lwt_unix.sendto server.fd str 0 len [] sockaddr
        >|= fun _ -> ()
    end

  end

  module Stream = struct

    (* Using Lwt_unix we share an implementation across various
       transport types *)
    module Fd = struct

      include Common

      type flow = {
        idx: int;
        description: string;
        fd: Lwt_unix.file_descr;
        read_buffer_size: int;
        mutable read_buffer: Cstruct.t;
        mutable closed: bool;
      }

      let of_fd
          ~idx ?(read_buffer_size = default_read_buffer_size) ~description fd
        =
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
          Log.err (fun f ->
              f "Socket.TCPV4.shutdown_read %s: caught %a returning Eof"
                description Fmt.exn e);
          Lwt.return ()

      let shutdown_write { description; fd; closed; _ } =
        try
          if not closed then Lwt_unix.shutdown fd Unix.SHUTDOWN_SEND;
          Lwt.return ()
        with
        | Unix.Unix_error(Unix.ENOTCONN, _, _) -> Lwt.return ()
        | e ->
          Log.err (fun f ->
              f "Socket.TCPV4.shutdown_write %s: caught %a returning Eof"
                description Fmt.exn e);
          Lwt.return ()

      let read t =
        if t.closed then Lwt.return (Ok `Eof)
        else begin
          if Cstruct.len t.read_buffer = 0
          then t.read_buffer <- Cstruct.create t.read_buffer_size;
          Lwt.catch (fun () ->
              Lwt_bytes.read t.fd t.read_buffer.Cstruct.buffer
                t.read_buffer.Cstruct.off t.read_buffer.Cstruct.len
              >|= function
              | 0 -> Ok `Eof
              | n ->
                let results = Cstruct.sub t.read_buffer 0 n in
                t.read_buffer <- Cstruct.shift t.read_buffer n;
                Ok (`Data results)
            ) (fun e ->
              Log.err (fun f ->
                  f "Socket.TCPV4.read %s: caught %a returning Eof"
                    t.description Fmt.exn e);
              Lwt.return (Ok `Eof)
            )
        end

      let read_into t buffer =
        if t.closed then Lwt.return (Ok `Eof)
        else Lwt.catch (fun () ->
            Lwt_cstruct.(complete (read t.fd) buffer) >|= fun () ->
            Ok (`Data ())
          ) (fun _e -> Lwt.return (Ok `Eof))

      let write t buf =
        if t.closed then Lwt.return (Error `Closed)
        else Lwt.catch (fun () ->
            Lwt_cstruct.(complete (write t.fd) buf) >|= fun () ->
            Ok ()
          ) (fun e ->
            Log.err (fun f ->
                f "Socket.TCPV4.write %s: caught %a returning Eof" t.description
                  Fmt.exn e);
            Lwt.return (Error `Closed)
          )

      let writev t bufs =
        let rec loop = function
        | []          -> Lwt.return (Ok ())
        | buf :: bufs ->
          if t.closed then Lwt.return (Error `Closed)
          else
            Lwt_cstruct.(complete (write t.fd) buf) >>= fun () ->
            loop bufs
        in
        Lwt.catch
          (fun () -> loop bufs)
          (fun e ->
             Log.err (fun f ->
                 f "Socket.TCPV4.writev %s: caught %a returning Eof"
                   t.description Fmt.exn e);
             Lwt.return (Error `Closed)
          )

      let close t =
        if not t.closed then begin
          t.closed <- true;
          Lwt_unix.close t.fd >|= fun () ->
          deregister_connection t.idx
        end else
          Lwt.return ()

      let connect
          description ?(read_buffer_size = default_read_buffer_size)
          sock_domain sock_ty sockaddr
        =
        register_connection description >>= fun idx ->
        let fd = Lwt_unix.socket sock_domain sock_ty 0 in
        Lwt.catch (fun () ->
            Log.debug (fun f -> f "%s: connecting" description);
            Lwt_unix.connect fd sockaddr >|= fun () ->
            Ok (of_fd ~idx ~read_buffer_size ~description fd)
          ) (fun e ->
            Lwt_unix.close fd >>= fun () ->
            deregister_connection idx;
            errorf "%s: Lwt_unix.connect: caught %a" description Fmt.exn e
          )

      type server = {
        mutable listening_fds: (int * Lwt_unix.file_descr) list;
        read_buffer_size: int;
        path: string; (* only for Win32 *)
        mutable closed: bool;
        mutable disable_connection_tracking: bool;
      }

      let make
          ?(read_buffer_size = default_read_buffer_size) ?(path="")
          listening_fds
        =
        { listening_fds; read_buffer_size; path; closed = false;
          disable_connection_tracking = false }

      let disable_connection_tracking server =
        server.disable_connection_tracking <- true

      let shutdown server =
        let fds = server.listening_fds in
        server.listening_fds <- [];
        server.closed <- true;
        Lwt_list.iter_s (fun (idx, fd) ->
            Lwt_unix.close fd >|= fun () ->
            deregister_connection idx
          ) fds

      let of_bound_fd ?(read_buffer_size = default_read_buffer_size) fd =
        let description = match Unix.getsockname fd with
        | Lwt_unix.ADDR_INET(iaddr, port) ->
          Fmt.strf "udp:%s:%d" (Unix.string_of_inet_addr iaddr) port
        | _ -> "unknown:"
        in
        let idx = register_connection_no_limit description in
        make ~read_buffer_size [ idx, Lwt_unix.of_unix_file_descr fd ]

      let listen server cb =
        let rec loop fd =
          Lwt_unix.accept fd >>= fun (client, sockaddr) ->
          let read_buffer_size = server.read_buffer_size in
          let description = string_of_sockaddr sockaddr in
          Lwt.async (fun () ->
              Lwt.catch (fun () ->
                  ( if server.disable_connection_tracking
                    then Lwt.return @@ register_connection_no_limit description
                    else register_connection description )
                  >|= fun idx ->
                  Some (of_fd ~idx ~read_buffer_size ~description client)
                ) (fun _e -> Lwt_unix.close client >|= fun () -> None)
              >>= function
              | None -> Lwt.return_unit
              | Some flow ->
                Lwt.finalize (fun () ->
                    log_exception_continue "Socket.Stream" (fun () -> cb flow)
                  ) (fun () -> close flow)
            );
          loop fd
        in
        List.iter (fun (_idx, fd) ->
            Lwt.async (fun () ->
                log_exception_continue "Socket.Stream" (fun () ->
                    Lwt.finalize (fun () ->
                        Lwt_unix.listen fd (!Utils.somaxconn);
                        loop fd
                      ) (fun () -> shutdown server)
                  )
              )
          ) server.listening_fds

    end

    module Tcp = struct
      include Fd

      type address = Ipaddr.t * int

      let connect ?read_buffer_size (ip, port) =
        let description = Fmt.strf "%a:%d" Ipaddr.pp_hum ip port in
        let sockaddr =
          Unix.ADDR_INET (Unix.inet_addr_of_string @@ Ipaddr.to_string ip, port)
        in
        let pf = match ip with
        | Ipaddr.V4 _ -> Lwt_unix.PF_INET
        | Ipaddr.V6 _ -> Lwt_unix.PF_INET6
        in
        connect description ?read_buffer_size pf Lwt_unix.SOCK_STREAM sockaddr

      let bind ?description (ip, port) =
        unix_bind ?description Lwt_unix.SOCK_STREAM (ip, port) >|= make

      let getsockname server = match server.listening_fds with
      | [] -> failwith "Tcp.getsockname: socket is closed"
      | (_idx, fd) :: _ ->
        match Lwt_unix.getsockname fd with
        | Lwt_unix.ADDR_INET(iaddr, port) ->
          Ipaddr.of_string_exn (Unix.string_of_inet_addr iaddr), port
        | _ -> invalid_arg "Tcp.getsockname passed a non-INET socket"
    end

    module Unix = struct
      include Fd

      type address = string

      let is_win32 = Sys.os_type = "win32"

      let connect ?read_buffer_size path =
        let description = "unix:" ^ path in
        if is_win32 then
          register_connection description>>= fun idx ->
          Named_pipe_lwt.Client.openpipe path >|= fun p ->
          let fd = Named_pipe_lwt.Client.to_fd p in
          Ok (of_fd ~idx ?read_buffer_size ~description fd)
        else
          let sockaddr = Unix.ADDR_UNIX path in
          connect description ?read_buffer_size Lwt_unix.PF_UNIX
            Lwt_unix.SOCK_STREAM sockaddr

      let bind ?(description="") path =
        let description = Fmt.strf "unix:%s %s" path description in
        if is_win32
        then Lwt.return (make ~path [])
        else
          Lwt.catch
            (fun () -> Lwt_unix.unlink path)
            (function
            | Unix.Unix_error(Unix.ENOENT, _, _) -> Lwt.return ()
            | e -> Lwt.fail e)
          >>= fun () ->
          register_connection description >>= fun idx ->
          let s = Lwt_unix.socket Lwt_unix.PF_UNIX Lwt_unix.SOCK_STREAM 0 in
          Lwt.catch (fun () ->
              Lwt_unix.bind s (Lwt_unix.ADDR_UNIX path) >|= fun () ->
              make ~path [ idx, s ]
            ) (fun e ->
              Lwt_unix.close s >>= fun () ->
              deregister_connection idx;
              Lwt.fail e
            )

      let listen server cb =
        let rec loop () =
          if server.closed
          then Lwt.return_unit
          else Lwt.catch (fun () ->
              let p = Named_pipe_lwt.Server.create server.path in
              Named_pipe_lwt.Server.connect p >>= fun () ->
              let description = "named-pipe:" ^ server.path in
              let read_buffer_size = server.read_buffer_size in
              let fd = Named_pipe_lwt.Server.to_fd p in
              Lwt.catch (fun () ->
                  (if server.disable_connection_tracking
                   then Lwt.return @@ register_connection_no_limit description
                   else register_connection description )
                  >|= fun idx ->
                  Some (of_fd ~idx ~read_buffer_size ~description fd)
                ) (fun _e -> Lwt_unix.close fd >|= fun () -> None)
              >>= function
              | None -> Lwt.return_unit
              | Some flow ->
                Lwt.async (fun () ->
                    Lwt.finalize (fun () ->
                        log_exception_continue "Socket.Stream.Unix"
                          (fun () -> cb flow)
                      ) (fun () -> close flow)
                  );
                loop ()
            ) (fun e ->
              Log.err (fun f ->
                  f "Named-pipe connection failed on %s: %a"
                    server.path Fmt.exn e);
              Lwt.return ()
            )
        in
        if not is_win32
        then listen server cb
        else Lwt.async (fun () ->
            log_exception_continue "Socket.Stream.Unix" (fun () -> loop ())
          )

      let getsockname server = server.path

      let unsafe_get_raw_fd t =
        (* By default Lwt sets fds to non-blocking mode. Reverse this
           to avoid surprising the caller. *)
        Lwt_unix.set_blocking ~set_flags:true t.fd true;
        Lwt_unix.unix_file_descr t.fd

    end

  end
end

module Files = struct

  let read_file path =
    Lwt.catch (fun () ->
        Lwt_unix.openfile path [ Lwt_unix.O_RDONLY ] 0 >>= fun fd ->
        let buffer = Buffer.create 128 in
        let frag = Bytes.make 1024 ' ' in
        Lwt.finalize (fun () ->
            let rec loop () =
              Lwt_unix.read fd frag 0 (Bytes.length frag) >>= function
              | 0 -> Lwt_result.return (Buffer.contents buffer)
              | n -> Buffer.add_substring buffer frag 0 n; loop ()
            in
            loop ()
          ) (fun () -> Lwt_unix.close fd)
      ) (fun e ->
        Lwt_result.fail (`Msg (Fmt.strf "reading %s: %a" path Fmt.exn e))
      )

  type watch = unit Lwt.t

  let watch_file path callback =
    (* Poll the file every 5s seconds *)
    let start () =
      Lwt_unix.stat path
      >>= function { Lwt_unix.st_mtime; _ } ->
        callback ();
        let rec poll st_mtime' =
          Lwt_unix.stat path >>= fun { Lwt_unix.st_mtime; _ } ->
          if st_mtime' <> st_mtime then callback ();
          Lwt_unix.sleep 5. >>= fun () ->
          poll st_mtime
        in
        poll st_mtime
    in
    (* On failure, wait another 5s and try again *)
    let rec loop () =
      Lwt.catch start (fun e ->
          Log.err (fun f -> f "While watching %s: %a" path Fmt.exn e);
          Lwt.return ()
        )
      >>= fun () ->
      Lwt_unix.sleep 5. >>= fun () ->
      loop ()
    in
    Ok (loop ())

  let unwatch = Lwt.cancel
end

module Time = Time

module Dns = struct

  (* FIXME: error handling completely missing *)
  let getaddrinfo host domain =
    let opts = [ Unix.AI_FAMILY domain ] in
    let service = "" in
    Lwt_unix.getaddrinfo host service opts
    >>= fun x ->
    Lwt.return @@
    List.fold_left (fun acc addr_info -> match addr_info.Unix.ai_addr with
      | Unix.ADDR_INET(ip, _) ->
        begin match Ipaddr.of_string @@ Unix.string_of_inet_addr ip with
        | Some ip -> ip :: acc
        | None -> acc
        end
      | _ -> acc
      ) [] x

  let localhost_local = Dns.Name.of_string "localhost.local"

  let resolve question =
    let open Dns.Packet in
    begin match question with
    | { q_class = Q_IN; q_name; _ } when q_name = localhost_local ->
      Log.debug (fun f -> f "DNS lookup of localhost.local: return NXDomain");
      Lwt.return (q_name, [])
    | { q_class = Q_IN; q_type = Q_A; q_name; _ } ->
      getaddrinfo (Dns.Name.to_string q_name) Unix.PF_INET >|= fun ips ->
      (q_name, ips)
    | { q_class = Q_IN; q_type = Q_AAAA; q_name; _ } ->
      getaddrinfo (Dns.Name.to_string q_name) Unix.PF_INET6 >|= fun ips ->
      (q_name, ips)
    | _ -> Lwt.return (Dns.Name.of_string "", [])
    end
    >>= function
    | _, [] -> Lwt.return []
    | q_name, ips ->
      let answers = List.map (function
        | Ipaddr.V4 v4 ->
          { name = q_name; cls = RR_IN; flush = false; ttl = 0l; rdata = A v4 }
        | Ipaddr.V6 v6 ->
          { name = q_name; cls = RR_IN; flush = false; ttl = 0l; rdata = AAAA v6 }
        ) ips
      in
      Lwt.return answers
end

module Main = struct
  let run = Lwt_main.run
  let run_in_main = Lwt_preemptive.run_in_main
end

module Fn = struct
  type ('request, 'response) t = 'request -> 'response
  let create f = f
  let destroy _ = ()
  let fn = Lwt_preemptive.detach
end

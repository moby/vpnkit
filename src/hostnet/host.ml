open Lwt.Infix

let src =
  let src = Logs.Src.create "Uwt" ~doc:"Host interface based on Uwt" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let default_read_buffer_size = 65536

let log_exception_continue description f =
  let to_string = function
    | Failure x -> x
    | e -> Printexc.to_string e in
  Lwt.catch
    (fun () -> f ())
    (fun e ->
       Log.warn (fun f -> f "%s: %s" description (to_string e));
       Lwt.return ()
    )

let make_sockaddr (ip, port) =
  Unix.ADDR_INET (Unix.inet_addr_of_string @@ Ipaddr.to_string ip, port)

let string_of_address (dst, dst_port) =
  Ipaddr.to_string dst ^ ":" ^ (string_of_int dst_port)

let sockaddr_of_address (dst, dst_port) =
  Unix.ADDR_INET(Unix.inet_addr_of_string @@ Ipaddr.to_string dst, dst_port)

module Common = struct
  (** FLOW boilerplate *)

  type error = [`Msg of string]
  type write_error = [Mirage_flow.write_error | error]
  let pp_error ppf (`Msg x) = Fmt.string ppf x

  let pp_write_error ppf = function
  | #Mirage_flow.write_error as e -> Mirage_flow.pp_write_error ppf e
  | #error as e                   -> pp_error ppf e

  let errorf fmt = Fmt.kstrf (fun s -> Lwt_result.fail (`Msg s)) fmt

  let ip_port_of_sockaddr sockaddr =
    try match sockaddr with
    | Unix.ADDR_INET(ip, port) ->
      Some (Ipaddr.of_string_exn @@ Unix.string_of_inet_addr ip, port)
    | _ -> None
    with _ -> None
end

module Sockets = struct

  let max_connections = ref None

  let set_max_connections x =
    begin match x with
      | None -> Log.info (fun f -> f "Removed connection limit")
      | Some limit -> Log.info (fun f -> f "Updated connection limit to %d" limit)
    end;
    max_connections := x

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
        Log.warn (fun f ->
            f "Exceeded maximum number of forwarded connections (%d)" m);
        last_error_log := now;
      end;
      Lwt.fail Too_many_connections
    | _ ->
      let idx = register_connection_no_limit description in
      Lwt.return idx

  let register_connection_noexn description =
    Lwt.catch (fun () -> register_connection description >>= fun idx -> Lwt.return (Some idx)) (fun _ -> Lwt.return None)

  let deregister_connection idx =
    if not(Hashtbl.mem connection_table idx) then begin
      Log.warn (fun f -> f "Deregistered connection %d more than once" idx)
    end;
    Hashtbl.remove connection_table idx

  module Datagram = struct
    type address = Ipaddr.t * int

    module Udp = struct
      include Common

      type flow = {
        idx: int option;
        label: string;
        description: string;
        mutable fd: Uwt.Udp.t option;
        read_buffer_size: int;
        mutable already_read: Cstruct.t option;
        sockaddr: Unix.sockaddr;
        address: address;
      }

      type address = Ipaddr.t * int

      let string_of_flow t = Fmt.strf "udp -> %s" (string_of_address t.address)

      let of_fd
          ?idx ?(read_buffer_size = Constants.max_udp_length)
          ?(already_read = None) ~description sockaddr address fd
        =
        let label = match fst address with
        | Ipaddr.V4 _ -> "UDPv4"
        | Ipaddr.V6 _ -> "UDPv6" in
        { idx; label; description; fd = Some fd; read_buffer_size; already_read;
          sockaddr; address }

      let connect ?read_buffer_size address =
        let description = "udp:" ^ (string_of_address address) in
        register_connection description
        >>= fun idx ->
        let label, fd, addr =
          try match fst @@ address with
          | Ipaddr.V4 _ -> "UDPv4", Uwt.Udp.init_ipv4_exn (), Unix.inet_addr_any
          | Ipaddr.V6 _ -> "UDPv6", Uwt.Udp.init_ipv6_exn (), Unix.inet6_addr_any
          with e -> deregister_connection idx; raise e
        in
        Lwt.catch (fun () ->
            let sockaddr = make_sockaddr address in
            let result = Uwt.Udp.bind fd ~addr:(Unix.ADDR_INET(addr, 0)) () in
            if not(Uwt.Int_result.is_ok result) then begin
              let error = Uwt.Int_result.to_error result in
              Log.err (fun f ->
                  f "Socket.%s.connect(%s): %s" label
                    (string_of_address address) (Uwt.strerror error));
              Lwt.fail (Unix.Unix_error(Uwt.to_unix_error error, "bind", ""))
            end else
              Lwt_result.return
                (of_fd ~idx ?read_buffer_size ~description sockaddr address fd)
          ) (fun e ->
            deregister_connection idx;
            log_exception_continue "Udp.connect Uwt.Udp.close_wait"
              (fun () -> Uwt.Udp.close_wait fd)
            >>= fun () ->
            errorf "Socket.%s.connect %s: caught %a" label description Fmt.exn e
          )

      let rec read t = match t.fd, t.already_read with
      | None, _ -> Lwt.return (Ok `Eof)
      | Some _, Some data when Cstruct.len data > 0 ->
        t.already_read <- Some (Cstruct.sub data 0 0); (* next read is `Eof *)
        Lwt.return (Ok (`Data data))
      | Some _, Some _ ->
        Lwt.return (Ok `Eof)
      | Some fd, None ->
        let buf = Cstruct.create t.read_buffer_size in
        Lwt.catch (fun () ->
            Uwt.Udp.recv_ba ~pos:buf.Cstruct.off ~len:buf.Cstruct.len
              ~buf:buf.Cstruct.buffer fd
            >>= fun recv ->
            if recv.Uwt.Udp.is_partial then begin
              Log.err (fun f ->
                  f "Socket.%s.read: dropping partial response (buffer \
                     was %d bytes)" t.label (Cstruct.len buf));
              read t
            end else begin
              let data = `Data (Cstruct.sub buf 0 recv.Uwt.Udp.recv_len) in
              (* Since we're emulating a point-to-point connection, drop any incoming
                 UDP which has the wrong source IP and port. *)
              match recv.Uwt.Udp.sockaddr with
              | Some sockaddr ->
                begin match ip_port_of_sockaddr sockaddr with
                | None ->
                  Log.warn (fun f ->
                    f "Socket.%s.read: packet has invalid source address so \
                       dropping since we're connected to %s" t.label
                      (string_of_address t.address)
                  );
                  read t
                | Some address when address <> t.address ->
                  Log.warn (fun f ->
                    f "Socket.%s.read: dropping response from %s since \
                       we're connected to %s" t.label
                      (string_of_address address)
                      (string_of_address t.address)
                  );
                  read t
                | Some _ ->
                  Lwt.return (Ok data)
                end
              | None ->
                Log.warn (fun f ->
                  f "Socket.%s.read: packet has no source address so \
                     dropping since we're connected to %s" t.label
                    (string_of_address t.address)
                );
                read t
            end
          ) (function
          | Unix.Unix_error(e, _, _) when Uwt.of_unix_error e = Uwt.ECANCELED ->
            (* happens on normal timeout *)
            Lwt.return (Ok `Eof)
          | e ->
            Log.err (fun f ->
                f "Socket.%s.read: %s caught %s returning Eof"
                  t.label
                  (string_of_flow t)
                  (Printexc.to_string e)
              );
            Lwt.return (Ok `Eof)
          )

      let write t buf = match t.fd with
      | None -> Lwt.return (Error `Closed)
      | Some fd ->
        Lwt.catch (fun () ->
            Uwt.Udp.send_ba ~pos:buf.Cstruct.off ~len:buf.Cstruct.len
              ~buf:buf.Cstruct.buffer fd t.sockaddr
            >>= fun () ->
            Lwt.return (Ok ())
          ) (fun e ->
            Log.err (fun f -> f "Socket.%s.write %s: caught %s returning Eof"
                        t.label t.description (Printexc.to_string e));
            Lwt.return (Error `Closed)
          )

      let writev t bufs = write t (Cstruct.concat bufs)

      let close t = match t.fd with
      | None -> Lwt.return_unit
      | Some fd ->
        t.fd <- None;
        Log.debug (fun f -> f "Socket.%s.close: %s" t.label (string_of_flow t));
        log_exception_continue "Udp.close Uwt.Udp.close_wait"
          (fun () -> Uwt.Udp.close_wait fd)
        >|= fun () ->
        match t.idx with Some idx -> deregister_connection idx | None -> ()

      let shutdown_read _t = Lwt.return_unit
      let shutdown_write _t = Lwt.return_unit

      type server = {
        idx: int;
        label: string;
        fd: Uwt.Udp.t;
        fd_mutex: Lwt_mutex.t;
        mutable closed: bool;
        mutable disable_connection_tracking: bool;
      }

      let make ~idx ~label fd =
        let fd_mutex = Lwt_mutex.create () in
        { idx; label; fd; fd_mutex; closed = false; disable_connection_tracking = false }

      let disable_connection_tracking server =
        server.disable_connection_tracking <- true

      let bind ?(description="") (ip, port) =
        let description =
          Fmt.strf "udp:%a:%d %s" Ipaddr.pp ip port description
        in
        let sockaddr = make_sockaddr(ip, port) in
        register_connection description >>= fun idx ->
        let fd =
          try Uwt.Udp.init ()
          with e -> deregister_connection idx; raise e
        in
        let result =
          Uwt.Udp.bind ~mode:[ Uwt.Udp.Reuse_addr ] fd ~addr:sockaddr ()
        in
        let label = match ip with
        | Ipaddr.V4 _ -> "UDPv4"
        | Ipaddr.V6 _ -> "UDPv6" in
        let t = make ~idx ~label fd in
        if not(Uwt.Int_result.is_ok result) then begin
          let error = Uwt.Int_result.to_error result in
          Log.debug (fun f ->
              f "Socket.%s.bind(%a, %d): %s" t.label Ipaddr.pp ip port
                (Uwt.strerror error));
          deregister_connection idx;
          Lwt.fail (Unix.Unix_error(Uwt.to_unix_error error, "bind", ""))
        end else Lwt.return t

      let of_bound_fd ?read_buffer_size:_ fd =
        match Uwt.Udp.openudp fd with
        | Uwt.Ok fd ->
          let label, description = match Uwt.Udp.getsockname fd with
          | Uwt.Ok sockaddr ->
            begin match ip_port_of_sockaddr sockaddr with
            | Some (ip, port) ->
              Fmt.strf "udp:%a:%d" Ipaddr.pp ip port,
              begin match ip with
              | Ipaddr.V4 _ -> "UDPv4"
              | Ipaddr.V6 _ -> "UDPv6"
              end
            | _ -> "unknown incoming UDP", "UDP?"
            end
          | Uwt.Error error ->
            "Socket.UDP?.of_bound_fd: getpeername failed: " ^ (Uwt.strerror error),
            "UDP?"
          in
          let idx = register_connection_no_limit description in
          make ~idx ~label fd
        | Uwt.Error error ->
          let msg =
            Fmt.strf "Socket.UDP?.of_bound_fd failed with %s" (Uwt.strerror error)
          in
          Log.err (fun f -> f "Socket.UDP?.of_bound_fd: %s" msg);
          failwith msg

      let getsockname { label; fd; _ } =
        match Uwt.Udp.getsockname_exn fd with
        | Unix.ADDR_INET(iaddr, port) ->
          Ipaddr.of_string_exn (Unix.string_of_inet_addr iaddr), port
        | _ ->
          Fmt.kstrf invalid_arg "Socket.%s.getsockname: passed a non-TCP socket"
            label

      let shutdown server =
        if not server.closed then begin
          server.closed <- true;
          log_exception_continue "Udp.shutdown Uwt.Udp.close_wait"
            (fun () -> Uwt.Udp.close_wait server.fd)
          >>= fun () ->
          deregister_connection server.idx;
          Lwt.return_unit
        end else Lwt.return_unit

      let rec recvfrom server buf =
        Uwt.Udp.recv_ba ~pos:buf.Cstruct.off ~len:buf.Cstruct.len
          ~buf:buf.Cstruct.buffer server.fd
        >>= fun recv ->
        if recv.Uwt.Udp.is_partial then begin
          Log.err (fun f ->
              f "Socket.%s.recvfrom: dropping partial response (buffer was \
                 %d bytes)" server.label (Cstruct.len buf));
          recvfrom server buf
        end else match recv.Uwt.Udp.sockaddr with
        | None ->
          Log.err (fun f ->
              f "Socket.%s.recvfrom: dropping response from unknown sockaddr"
                server.label);
          recvfrom server buf
        | Some sockaddr ->
          begin match ip_port_of_sockaddr sockaddr with
          | Some address -> Lwt.return (recv.Uwt.Udp.recv_len, address)
          | None ->
            Log.err (fun f ->
              f "Socket.%s.recvfrom: dropping response from invalid sockaddr"
                server.label);
            recvfrom server buf
          end

      let listen t flow_cb =
        let rec loop () =
          Lwt.catch (fun () ->
              (* Allocate a fresh buffer because the packet will be
                 processed in a background thread *)
              let buffer = Cstruct.create Constants.max_udp_length in
              recvfrom t buffer
              >>= fun (n, address) ->
              let data = Cstruct.sub buffer 0 n in
              (* construct a flow with this buffer available for reading *)
              (* No new fd so no new idx *)
              let description = Fmt.strf "udp:%s" (string_of_address address) in
              let flow =
                of_fd ~description ~read_buffer_size:0 ~already_read:(Some data)
                  (sockaddr_of_address address) address t.fd
              in
              Lwt.async (fun () ->
                  Lwt.catch
                    (fun () -> flow_cb flow)
                    (fun e ->
                       Log.info (fun f -> f "Socket.%s.listen callback caught: %s"
                                    t.label (Printexc.to_string e)
                                );
                       Lwt.return_unit
                    )
                );
              Lwt.return true
            ) (fun e ->
              Log.err (fun f -> f "Socket.%s.listen caught %s shutting down server"
                          t.label(Printexc.to_string e)
                      );
              Lwt.return false
            )
          >>= function
          | false -> Lwt.return_unit
          | true -> loop ()
        in
        Lwt.async loop

      let sendto server (ip, port) ?(ttl=64) buf =
        (* Avoid a race between the setSocketTTL and the send_ba *)
        Lwt_mutex.with_lock server.fd_mutex
          (fun () ->
            begin match Uwt.Udp.fileno server.fd with
            | Error _ -> ()
            | Ok fd -> Utils.setSocketTTL fd ttl
            end;
            let sockaddr =
              Unix.ADDR_INET(Unix.inet_addr_of_string @@ Ipaddr.to_string ip, port)
            in
            Uwt.Udp.send_ba ~pos:buf.Cstruct.off ~len:buf.Cstruct.len
              ~buf:buf.Cstruct.buffer server.fd sockaddr
          )
    end

  end

  module Stream = struct
    module Tcp = struct
      include Common

      type address = Ipaddr.t * int

      type flow = {
        idx: int;
        label: string;
        description: string;
        fd: Uwt.Tcp.t;
        read_buffer_size: int;
        mutable read_buffer: Cstruct.t;
        mutable closed: bool;
      }

      let of_fd ~idx ~label ?(read_buffer_size = default_read_buffer_size)
          ~description fd =
        let read_buffer = Cstruct.create read_buffer_size in
        let closed = false in
        { idx; label; description; fd; read_buffer; read_buffer_size; closed }

      let connect ?(read_buffer_size = default_read_buffer_size) (ip, port) =
        let description = Fmt.strf "tcp:%a:%d" Ipaddr.pp ip port in
        let label = match ip with
        | Ipaddr.V4 _ -> "TCPv4"
        | Ipaddr.V6 _ -> "TCPv6" in
        register_connection_noexn description
        >>= function
        | None ->
          errorf "Socket.%s.connect %s: hit connection limit" label description
        | Some idx ->
          let fd =
            try match ip with
            | Ipaddr.V4 _ -> Uwt.Tcp.init_ipv4_exn ()
            | Ipaddr.V6 _ -> Uwt.Tcp.init_ipv6_exn ()
            with e -> deregister_connection idx; raise e in
          Lwt.catch (fun () ->
              let sockaddr = make_sockaddr (ip, port) in
              Uwt.Tcp.connect fd ~addr:sockaddr >>= fun () ->
              let error = Uwt.Tcp.enable_keepalive fd 1 in
              if Uwt.Int_result.is_error error then begin
                Log.warn (fun f ->
                f "Uwt.Tcp.enable_keepalive failed with: %s"
                  (Uwt.strerror @@ Uwt.Int_result.to_error error))
              end;
              let error = Uwt.Tcp.nodelay fd true in
              if Uwt.Int_result.is_error error then begin
                Log.warn (fun f ->
                f "Uwt.Tcp.nodelay failed with: %s"
                  (Uwt.strerror @@ Uwt.Int_result.to_error error))
              end;
              of_fd ~idx ~label ~read_buffer_size ~description fd
              |> Lwt_result.return
            ) (fun e ->
              deregister_connection idx;
              log_exception_continue "Tcp.connect Uwt.Tcp.close_wait"
                (fun () -> Uwt.Tcp.close_wait fd)
              >>= fun () ->
              errorf "Socket.%s.connect %s: caught %a" label description Fmt.exn e
            )

      let shutdown_read _ =
        Lwt.return ()

      let shutdown_write { label; description; fd; closed; _ } =
        try if not closed then Uwt.Tcp.shutdown fd else Lwt.return ()
        with
        | Unix.Unix_error(Unix.ENOTCONN, _, _) -> Lwt.return ()
        | e ->
          Log.err (fun f ->
              f "Socket.%s.shutdown_write %s: caught %a returning Eof"
                label description Fmt.exn e);
          Lwt.return ()

      let read_into t buf =
        let rec loop buf =
          if Cstruct.len buf = 0
          then Lwt.return (Ok (`Data ()))
          else
            Uwt.Tcp.read_ba ~pos:buf.Cstruct.off ~len:buf.Cstruct.len t.fd
              ~buf:buf.Cstruct.buffer
            >>= function
            | 0 -> Lwt.return (Ok `Eof)
            | n -> loop (Cstruct.shift buf n)
        in
        loop buf

      let read t =
        (if Cstruct.len t.read_buffer = 0
         then t.read_buffer <- Cstruct.create t.read_buffer_size);
        Lwt.catch (fun () ->
            Uwt.Tcp.read_ba ~pos:t.read_buffer.Cstruct.off
              ~len:t.read_buffer.Cstruct.len t.fd
              ~buf:t.read_buffer.Cstruct.buffer
            >>= function
            | 0 -> Lwt.return (Ok `Eof)
            | n ->
              let results = Cstruct.sub t.read_buffer 0 n in
              t.read_buffer <- Cstruct.shift t.read_buffer n;
              Lwt.return (Ok (`Data results))
          ) (function
          | Unix.Unix_error(Unix.ECONNRESET, _, _) ->
            Lwt.return (Ok `Eof)
          | Unix.Unix_error(e, _, _) when Uwt.of_unix_error e = Uwt.ECANCELED ->
            Lwt.return (Ok `Eof)
          | e ->
            Log.err (fun f ->
                f "Socket.%s.read %s: caught %s returning Eof" t.label
                  t.description (Printexc.to_string e));
            Lwt.return (Ok `Eof)
          )

      let write t buf =
        Lwt.catch (fun () ->
            Uwt.Tcp.write_ba ~pos:buf.Cstruct.off ~len:buf.Cstruct.len t.fd
              ~buf:buf.Cstruct.buffer
            >>= fun () ->
            Lwt.return (Ok ())
          ) (function
          | Unix.Unix_error(Unix.ECONNRESET, _, _) ->
            Lwt.return (Error `Closed)
          | Unix.Unix_error(e, _, _) when Uwt.of_unix_error e = Uwt.ECANCELED ->
            Lwt.return (Error `Closed)
          | e ->
            Log.err (fun f ->
                f "Socket.%s.write %s: caught %s returning Eof" t.label
                  t.description (Printexc.to_string e));
            Lwt.return (Error `Closed)
          )

      let writev t bufs =
        Lwt.catch (fun () ->
            let rec loop = function
            | [] -> Lwt.return (Ok ())
            | buf :: bufs ->
              Uwt.Tcp.write_ba ~pos:buf.Cstruct.off ~len:buf.Cstruct.len t.fd
                ~buf:buf.Cstruct.buffer
              >>= fun () ->
              loop bufs
            in
            loop bufs
          ) (function
          | Unix.Unix_error(Unix.ECONNRESET, _, _) ->
            Lwt.return (Error `Closed)
          | Unix.Unix_error(e, _, _) when Uwt.of_unix_error e = Uwt.ECANCELED ->
            Lwt.return (Error `Closed)
          | e ->
            Log.err (fun f ->
                f "Socket.%s.writev %s: caught %s returning Eof" t.label
                  t.description (Printexc.to_string e));
            Lwt.return (Error `Closed)
          )

      let close t =
        if not t.closed then begin
          t.closed <- true;
          log_exception_continue "Tcp.close Uwt.Tcp.close_wait"
            (fun () -> Uwt.Tcp.close_wait t.fd)
          >>= fun () ->
          deregister_connection t.idx;
          Lwt.return ()
        end else Lwt.return ()

      type server = {
        label: string;
        mutable listening_fds: (int * Uwt.Tcp.t) list;
        read_buffer_size: int;
        mutable disable_connection_tracking: bool;
      }

      let getsockname' = function
      | [] -> failwith "Tcp.getsockname: socket is closed"
      | (_, fd) :: _ ->
        match Uwt.Tcp.getsockname_exn fd with
        | Unix.ADDR_INET(iaddr, port) ->
          Ipaddr.of_string_exn (Unix.string_of_inet_addr iaddr), port
        | _ -> invalid_arg "Tcp.getsockname passed a non-TCP socket"

      let make ?(read_buffer_size = default_read_buffer_size) listening_fds =
        let label = match getsockname' listening_fds with
        | Ipaddr.V4 _, _ -> "TCPv4"
        | Ipaddr.V6 _, _ -> "TCPv6" in
        { label; listening_fds; read_buffer_size;
          disable_connection_tracking = false }

      let disable_connection_tracking server =
        server.disable_connection_tracking <- true

      let getsockname server = getsockname' server.listening_fds

      let bind_one ?(description="") (ip, port) =
        let description =
          Fmt.strf "tcp:%a:%d %s" Ipaddr.pp ip port description
        in
        register_connection description >>= fun idx ->
        let fd =
          try Uwt.Tcp.init ()
          with e -> deregister_connection idx; raise e
        in
        let addr = make_sockaddr (ip, port) in
        let result = Uwt.Tcp.bind fd ~addr () in
        let label = match ip with
        | Ipaddr.V4 _ -> "TCPv4"
        | Ipaddr.V6 _ -> "TCPv6" in
        if not(Uwt.Int_result.is_ok result) then begin
          let error = Uwt.Int_result.to_error result in
          let msg =
            Fmt.strf "Socket.%s.bind(%s, %d): %s" label (Ipaddr.to_string ip)
              port (Uwt.strerror error)
          in
          Log.err (fun f -> f "Socket.%s.bind: %s" label msg);
          deregister_connection idx;
          Lwt.fail (Unix.Unix_error(Uwt.to_unix_error error, "bind", ""))
        end else Lwt.return (idx, label, fd)

      let bind ?description (ip, port) =
        bind_one ?description (ip, port)
        >>= fun (idx, label, fd) ->
        ( match Uwt.Tcp.getsockname fd with
        | Uwt.Ok sockaddr ->
          begin match ip_port_of_sockaddr sockaddr with
          | Some (_, local_port) -> Lwt.return local_port
          | _ -> assert false
          end
        | Uwt.Error error ->
          let msg =
            Fmt.strf "Socket.%s.bind(%a, %d): %s" label Ipaddr.pp ip port
              (Uwt.strerror error)
          in
          Log.debug (fun f -> f "Socket.%s.bind: %s" label msg);
          deregister_connection idx;
          Lwt.fail (Unix.Unix_error(Uwt.to_unix_error error, "bind", "")) )
        >>= fun local_port ->
        (* On some systems localhost will resolve to ::1 first and this can
           cause performance problems (particularly on Windows). Perform a
           best-effort bind to the ::1 address. *)
        Lwt.catch (fun () ->
            if Ipaddr.compare ip (Ipaddr.V4 Ipaddr.V4.localhost) = 0
            || Ipaddr.compare ip (Ipaddr.V4 Ipaddr.V4.any) = 0
            then begin
              Log.debug (fun f ->
                  f "Attempting a best-effort bind of ::1:%d" local_port);
              bind_one (Ipaddr.(V6 V6.localhost), local_port)
              >>= fun (idx, _, fd) ->
              Lwt.return [ idx, fd ]
            end else
              Lwt.return []
          ) (fun e ->
            Log.debug (fun f ->
                f "Ignoring failed bind to ::1:%d (%a)" local_port Fmt.exn e);
            Lwt.return []
          )
        >|= fun extra ->
        make ((idx, fd) :: extra)

      let shutdown server =
        let fds = server.listening_fds in
        server.listening_fds <- [];
        Lwt_list.iter_s (fun (idx, fd) ->
            log_exception_continue "Tcp.shutdown: Uwt.Tcp.close_wait"
              (fun () -> Uwt.Tcp.close_wait fd)
            >|= fun () ->
            deregister_connection idx;
          ) fds

      let of_bound_fd ?(read_buffer_size = default_read_buffer_size) fd =
        let description = match Unix.getsockname fd with
        | Unix.ADDR_INET(iaddr, port) ->
          Fmt.strf "tcp:%s:%d" (Unix.string_of_inet_addr iaddr) port
        | _ -> "of_bound_fd: unknown TCP socket" in
        let fd = Uwt.Tcp.opentcp_exn fd in
        let idx = register_connection_no_limit description in
        make ~read_buffer_size [ (idx, fd) ]

      let listen server' cb =
        List.iter (fun (_, fd) ->
            let cb server x =
              try
                if Uwt.Int_result.is_error x then
                  Log.err (fun f ->
                      f "Uwt.Tcp.listen callback failed with: %s"
                        (Uwt.strerror @@ Uwt.Int_result.to_error x))
                else
                  let client = Uwt.Tcp.init () in
                  let t = Uwt.Tcp.accept_raw ~server ~client in
                  if Uwt.Int_result.is_error t then begin
                    Log.err (fun f ->
                        f "Uwt.Tcp.accept_raw failed with: %s"
                          (Uwt.strerror @@ Uwt.Int_result.to_error t))
                  end else begin
                    let error = Uwt.Tcp.enable_keepalive client 1 in
                    if Uwt.Int_result.is_error error then begin
                      Log.warn (fun f ->
                      f "Uwt.Tcp.enable_keepalive failed with: %s"
                        (Uwt.strerror @@ Uwt.Int_result.to_error error))
                    end;
                    let error = Uwt.Tcp.nodelay client true in
                    if Uwt.Int_result.is_error error then begin
                      Log.warn (fun f ->
                      f "Uwt.Tcp.nodelay failed with: %s"
                        (Uwt.strerror @@ Uwt.Int_result.to_error error))
                    end;
                    let label, description =
                      match Uwt.Tcp.getpeername client with
                      | Uwt.Ok sockaddr ->
                        begin match ip_port_of_sockaddr sockaddr with
                        | Some (ip, port) ->
                          Fmt.strf "tcp:%s:%d" (Ipaddr.to_string ip) port,
                          begin match ip with
                          | Ipaddr.V4 _ -> "TCPv4"
                          | Ipaddr.V6 _ -> "TCPv6"
                          end
                        | _ -> "unknown incoming TCP", "TCP"
                        end
                      | Uwt.Error error ->
                        "getpeername failed: " ^ (Uwt.strerror error), "TCP"
                    in

                    Lwt.async (fun () ->
                        Lwt.catch (fun () ->
                            (if server'.disable_connection_tracking
                             then
                               Lwt.return @@
                               register_connection_no_limit description
                             else register_connection description )
                            >|= fun idx ->
                            Some (of_fd ~idx ~label ~description client)
                          ) (fun _e ->
                            log_exception_continue "Tcp.listen Uwt.Tcp.close_wait"
                              (fun () -> Uwt.Tcp.close_wait client)
                            >>= fun () ->
                            Lwt.return_none
                          ) >>= function
                        | None -> Lwt.return_unit
                        | Some flow ->
                          log_exception_continue "listen" (fun () ->
                              Lwt.finalize (fun () ->
                                  log_exception_continue "Socket.Stream"
                                    (fun () -> cb flow)
                                ) (fun () -> close flow)
                            ))
                  end
              with e ->
                Log.err (fun f ->
                    f "Uwt.Tcp.listen callback raised: %a" Fmt.exn e)
            in
            let listen_result = Uwt.Tcp.listen fd ~max:(!Utils.somaxconn) ~cb in
            if Uwt.Int_result.is_error listen_result
            then Log.err (fun f ->
                f "Uwt.Tcp.listen failed with: %s"
                  (Uwt.strerror @@ Uwt.Int_result.to_error listen_result))
          ) server'.listening_fds

    end

    module Unix = struct
      include Common

      type address = string

      type flow = {
        idx: int;
        description: string;
        fd: Uwt.Pipe.t;
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

      let unsafe_get_raw_fd t =
        let fd = Uwt.Pipe.fileno_exn t.fd in
        Unix.clear_nonblock fd;
        fd

      let connect ?(read_buffer_size = default_read_buffer_size) path =
        let description = "unix:" ^ path in
        register_connection description
        >>= fun idx ->
        let fd = Uwt.Pipe.init () in
        Lwt.catch
          (fun () ->
             Uwt.Pipe.connect fd ~path
             >>= fun () ->
             let description = path in
             Lwt_result.return (of_fd ~idx ~read_buffer_size ~description fd)
          ) (fun e ->
              deregister_connection idx;
              Lwt.fail e
            )

      let shutdown_read _ =
        Lwt.return ()

      let shutdown_write { description; fd; closed; _ } =
        try
          if not closed then Uwt.Pipe.shutdown fd else Lwt.return ()
        with
        | Unix.Unix_error(Unix.ENOTCONN, _, _) -> Lwt.return ()
        | e ->
          Log.err (fun f ->
              f "Socket.Pipe.shutdown_write %s: caught %a returning Eof"
                description Fmt.exn e);
          Lwt.return ()

      let read_into t buf =
        let rec loop buf =
          if Cstruct.len buf = 0
          then Lwt.return (Ok (`Data ()))
          else
            Uwt.Pipe.read_ba ~pos:buf.Cstruct.off ~len:buf.Cstruct.len t.fd
              ~buf:buf.Cstruct.buffer
            >>= function
            | 0 -> Lwt.return (Ok `Eof)
            | n -> loop (Cstruct.shift buf n)
        in
        loop buf

      let read t =
        (if Cstruct.len t.read_buffer = 0
         then t.read_buffer <- Cstruct.create t.read_buffer_size);
        Lwt.catch (fun () ->
            Uwt.Pipe.read_ba ~pos:t.read_buffer.Cstruct.off
              ~len:t.read_buffer.Cstruct.len t.fd
              ~buf:t.read_buffer.Cstruct.buffer
            >>= function
            | 0 -> Lwt.return (Ok `Eof)
            | n ->
              let results = Cstruct.sub t.read_buffer 0 n in
              t.read_buffer <- Cstruct.shift t.read_buffer n;
              Lwt.return (Ok (`Data results))
          ) (fun e ->
            Log.err (fun f ->
                f "Socket.Pipe.read %s: caught %a returning Eof"
                  t.description Fmt.exn e);
            Lwt.return (Ok `Eof)
          )

      let write t buf =
        Lwt.catch (fun () ->
            Uwt.Pipe.write_ba ~pos:buf.Cstruct.off ~len:buf.Cstruct.len t.fd
              ~buf:buf.Cstruct.buffer
            >|= fun () ->
            Ok ()
          ) (function
          | Unix.Unix_error(Unix.EPIPE, _, _) ->
            (* other end has closed, this is normal *)
            Lwt.return (Error `Closed)
          | e ->
            (* Unexpected error *)
            Log.err (fun f ->
                f "Socket.Pipe.write %s: caught %a returning Eof"
                  t.description Fmt.exn e);
            Lwt.return (Error `Closed)
          )

      let writev t bufs =
        Lwt.catch (fun () ->
            let rec loop = function
            | [] -> Lwt.return (Ok ())
            | buf :: bufs ->
              Uwt.Pipe.write_ba ~pos:buf.Cstruct.off ~len:buf.Cstruct.len t.fd
                ~buf:buf.Cstruct.buffer
              >>= fun () ->
              loop bufs
            in
            loop bufs
          ) (fun e ->
            Log.err (fun f ->
                f "Socket.Pipe.writev %s: caught %a returning Eof"
                  t.description Fmt.exn e);
            Lwt.return (Error `Closed)
          )

      let close t =
        if not t.closed then begin
          t.closed <- true;
          log_exception_continue "Unix.close Uwt.Pipe.close_wait"
            (fun () -> Uwt.Pipe.close_wait t.fd)
          >|= fun () ->
          deregister_connection t.idx
        end else Lwt.return ()

      type server = {
        idx: int;
        fd: Uwt.Pipe.t;
        mutable closed: bool;
        mutable disable_connection_tracking: bool;
      }

      let bind ?(description="") path =
        Lwt.catch (fun () -> Uwt.Fs.unlink path) (fun _ -> Lwt.return ())
        >>= fun () ->
        let description = Fmt.strf "unix:%s %s" path description in
        register_connection description >>= fun idx ->
        let fd = Uwt.Pipe.init () in
        Lwt.catch (fun () ->
            Uwt.Pipe.bind_exn fd ~path;
            Lwt.return { idx; fd; closed = false;
                         disable_connection_tracking = false }
          ) (fun e ->
            deregister_connection idx;
            Lwt.fail e
          )

      let getsockname server = match Uwt.Pipe.getsockname server.fd with
      | Uwt.Ok path -> path
      | _ -> invalid_arg "Unix.sockname passed a non-Unix socket"

      let disable_connection_tracking server =
        server.disable_connection_tracking <- true

      let listen ({ fd; _ } as server') cb =
        let cb server x =
          try
            if Uwt.Int_result.is_error x then
              Log.err (fun f ->
                  f "Uwt.Pipe.listen callback failed with: %s"
                    (Uwt.strerror @@ Uwt.Int_result.to_error x))
            else
              let client = Uwt.Pipe.init () in
              let t = Uwt.Pipe.accept_raw ~server ~client in
              if Uwt.Int_result.is_error t then begin
                Log.err (fun f ->
                    f "Uwt.Pipe.accept_raw failed with: %s"
                      (Uwt.strerror @@ Uwt.Int_result.to_error t))
              end else begin
                Lwt.async (fun () ->
                    Lwt.catch (fun () ->
                        let description = "unix:" ^ getsockname server' in
                        (if server'.disable_connection_tracking
                         then Lwt.return @@
                           register_connection_no_limit description
                         else register_connection description )
                        >|= fun idx ->
                        Some (of_fd ~idx ~description client)
                      ) (fun _e ->
                        log_exception_continue "Unix.listen Uwt.Pipe.close_wait"
                          (fun () -> Uwt.Pipe.close_wait client)
                        >>= fun () ->
                        Lwt.return_none
                      )
                    >>= function
                    | None -> Lwt.return_unit
                    | Some flow ->
                      Lwt.finalize (fun () ->
                          log_exception_continue "Pipe.listen"
                            (fun () -> cb flow)
                        ) (fun () -> close flow )
                  )
              end
          with e ->
            Log.err (fun f -> f "Uwt.Pipe.listen callback raised: %a" Fmt.exn e)
        in
        let listen_result = Uwt.Pipe.listen fd ~max:(!Utils.somaxconn) ~cb in
        if Uwt.Int_result.is_error listen_result
        then Log.err (fun f ->
            f "Uwt.Pipe.listen failed with: %s"
              (Uwt.strerror @@ Uwt.Int_result.to_error listen_result))

      let of_bound_fd ?(read_buffer_size = default_read_buffer_size) fd =
        match Uwt.Pipe.openpipe fd with
        | Uwt.Ok fd ->
          let description = match Uwt.Pipe.getsockname fd with
          | Uwt.Ok path -> "unix:" ^ path
          | Uwt.Error error -> "getsockname failed: " ^ (Uwt.strerror error)
          in
          let idx = register_connection_no_limit description in
          { idx; fd; closed = false; disable_connection_tracking = false }
        | Uwt.Error error ->
          let msg =
            Fmt.strf "Socket.Pipe.of_bound_fd (read_buffer_size=%d) failed \
                      with %s" read_buffer_size (Uwt.strerror error)
          in
          Log.err (fun f -> f "%s" msg);
          failwith msg

      let shutdown server =
        if not server.closed then begin
          server.closed <- true;
          log_exception_continue "Unix.shutdown Uwt.Pipe.close_wait"
            (fun () -> Uwt.Pipe.close_wait server.fd)
          >|= fun () ->
          deregister_connection server.idx
        end else
          Lwt.return_unit
    end
  end
end

module Files = struct
  let read_file path =
    let open Lwt.Infix in
    Lwt.catch
      (fun () ->
         Uwt.Fs.openfile ~mode:[ Uwt.Fs_types.O_RDONLY ] path
         >>= fun file ->
         let buffer = Buffer.create 128 in
         let frag = Bytes.make 1024 ' ' in
         Lwt.finalize
           (fun () ->
              let rec loop () =
                Uwt.Fs.read file ~buf:frag
                >>= function
                | 0 ->
                  Lwt_result.return (Buffer.contents buffer)
                | n ->
                  Buffer.add_subbytes buffer frag 0 n;
                  loop () in
              loop ()
           ) (fun () ->
               Uwt.Fs.close file
             )
      ) (fun e ->
          Lwt_result.fail (`Msg (Fmt.strf "reading %s: %a" path Fmt.exn e))
        )

  (* NOTE(djs55): Fs_event didn't work for me on MacOS *)
  type watch = Uwt.Fs_poll.t

  let unwatch w = Uwt.Fs_poll.close_noerr w

  let watch_file path callback =
    let cb _h res = match res with
    | Ok _ ->
      callback ()
    | Error err ->
      Log.err (fun f -> f "While watching %s: %s" path (Uwt.err_name err));
      () in
    match Uwt.Fs_poll.start path 5000 ~cb with
    | Ok handle ->
      callback ();
      Ok handle
    | Error err ->
      Log.err (fun f -> f "Starting to watch %s: %s" path (Uwt.err_name err));
      Error (`Msg (Uwt.strerror err))

end

module Time = struct
  let sleep_ns x = Uwt.Timer.sleep (Duration.to_ms x)
end

module Dns = struct
  (* FIXME: error handling completely missing *)
  let getaddrinfo host domain =
    let opts = [ Unix.AI_FAMILY domain ] in
    let service = "" in
    Uwt.Dns.getaddrinfo ~host ~service opts
    >>= function
    | Error _ ->
      Lwt.return []
    | Ok x ->
      Lwt.return @@
      List.fold_left (fun acc addr_info -> match addr_info.Uwt.Dns.ai_addr with
        | Unix.ADDR_INET(ip, _) ->
          begin match Ipaddr.of_string @@ Unix.string_of_inet_addr ip with
          | Ok ip -> ip :: acc
          | Error _ -> acc
          end
        | _ -> acc
        ) [] x

  let localhost_local = Dns.Name.of_string "localhost.local"

  let resolve_getaddrinfo question =
    let open Dns.Packet in
    begin match question with
    | { q_class = Q_IN; q_name; _ } when q_name = localhost_local ->
      Log.debug (fun f -> f "DNS lookup of localhost.local: return NXDomain");
      Lwt.return (q_name, [])
    | { q_class = Q_IN; q_type = Q_A; q_name; _ } ->
      getaddrinfo (Dns.Name.to_string q_name) Unix.PF_INET
      >>= fun ips ->
      Lwt.return (q_name, ips)
    | { q_class = Q_IN; q_type = Q_AAAA; q_name; _ } ->
      getaddrinfo (Dns.Name.to_string q_name) Unix.PF_INET6
      >>= fun ips ->
      Lwt.return (q_name, ips)
    | _ ->
      Lwt.return (Dns.Name.of_string "", [])
    end
    >>= function
    | _, [] -> Lwt.return []
    | q_name, ips ->
      let answers = List.map (function
        | Ipaddr.V4 v4 ->
          { name = q_name; cls = RR_IN; flush = false; ttl = 0l; rdata = A v4 }
        | Ipaddr.V6 v6 ->
          { name = q_name; cls = RR_IN; flush = false; ttl = 0l; rdata = AAAA v6 }
        ) ips in
      Lwt.return answers

  let resolve = resolve_getaddrinfo
end

module Main = struct
  let run = Uwt.Main.run
  let run_in_main = Uwt_preemptive.run_in_main
end

module Fn = struct
  type ('request, 'response) t = 'request -> 'response
  let create f = f
  let destroy _ = ()
  let fn = Uwt_preemptive.detach
end

let compact () =
  let start = Unix.gettimeofday () in
  Gc.compact();
  let stats = Gc.stat () in
  let time = Unix.gettimeofday () -. start in

  Log.info (fun f -> f
    "Gc.compact took %.1f seconds. Heap has heap_words=%d live_words=%d free_words=%d top_heap_words=%d stack_size=%d"
    time stats.Gc.heap_words stats.Gc.live_words stats.Gc.free_words stats.Gc.top_heap_words stats.Gc.stack_size
  )

let start_background_gc config =
  let () = match config with
  | None ->
    Log.info (fun f -> f "No periodic Gc.compact enabled")
  | Some s ->
    let rec loop () =
      Time.sleep_ns (Duration.of_sec s)
      >>= fun () ->
      compact ();
      loop () in
    Lwt.async loop
  in
  if Sys.os_type = "Unix" then begin
    (* This fails with EINVAL on Windows *)
    let (_: Uwt.Signal.t) = Uwt.Signal.start_exn Sys.sigusr1 ~cb:(fun _t _signal ->
        Log.info (fun f -> f "Received SIGUSR1");
        compact ()
    ) in
    ()
  end
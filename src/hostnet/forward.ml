open Lwt.Infix

let src =
  let src =
    Logs.Src.create "port forward" ~doc:"forward local ports to the VM"
  in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let log_exception_continue description f =
  Lwt.catch
    (fun () -> f ())
    (fun e ->
       Log.warn (fun f -> f "%s: caught %a" description Fmt.exn e);
       Lwt.return ())

let allowed_addresses = ref None

let set_allowed_addresses ips =
  Log.info (fun f -> f "allowing binds to %s" (match ips with
    | None     -> "any IP addresses"
    | Some ips -> String.concat ", " (List.map Ipaddr.to_string ips)
    ));
  allowed_addresses := ips

let errorf fmt = Fmt.kstrf (fun e -> Error (`Msg e)) fmt
let errorf' fmt = Fmt.kstrf (fun e -> Lwt.return (Error (`Msg e))) fmt

module Port = struct
  type t = Forwarder.Frame.Destination.t

  let to_string = function
    | `Tcp (ip, port) ->
      Fmt.strf "tcp:%a:%d" Ipaddr.pp ip port
    | `Udp (ip, port) ->
      Fmt.strf "udp:%a:%d" Ipaddr.pp ip port
    | `Unix path ->
      Fmt.strf "unix:%s" (Base64.encode_exn path)

  let of_string x =
    try
      match Stringext.split ~on:':' x with
      | [ proto; ip; port ] ->
        let port = int_of_string port in
        let ip = Ipaddr.of_string_exn ip in
        begin match String.lowercase_ascii proto with
        | "tcp" -> Ok (`Tcp(ip, port))
        | "udp" -> Ok (`Udp(ip, port))
        | _ -> errorf "unknown protocol: should be tcp or udp"
        end
      | [ "unix"; path ] -> Ok (`Unix (Base64.decode_exn path))
      | _ -> errorf "port should be of the form proto:IP:port or unix:path"
    with
    | _ -> errorf "port is not a proto:IP:port or unix:path: '%s'" x

end

module Make
    (Clock: Mirage_clock_lwt.MCLOCK)
    (Connector: Sig.Connector)
    (Socket: Sig.SOCKETS) =
struct

  type server = [
    | `Tcp of Socket.Stream.Tcp.server
    | `Udp of Socket.Datagram.Udp.server
    | `Unix of Socket.Stream.Unix.server
  ]

  type t = {
    mutable local: Port.t;
    remote_port: Port.t;
    mutable server: server option;
  }

  type key = Port.t

  let get_key t = t.local

  type clock = Clock.t

  let to_string t =
    Fmt.strf "%s:%s" (Port.to_string t.local) (Port.to_string t.remote_port)

  let description_of_format =
    "tcp:<local IP>:<local port>:tcp:<remote IP>:<remote port>
udp:<local IP>:<local port>:udp:<remote IP>:<remote port>
unix:<base64-encoded local path>:unix:<base64-encoded remote path>"

  let check_bind_allowed ip = match !allowed_addresses with
  | None -> Lwt.return () (* no restriction *)
  | Some ips ->
    let match_ip allowed_ip =
      let exact_match = Ipaddr.compare allowed_ip ip = 0 in
      let wildcard = match ip, allowed_ip with
      | Ipaddr.V4 _, Ipaddr.V4 x when x = Ipaddr.V4.any -> true
      | _, _ -> false
      in
      exact_match || wildcard
    in
    if List.fold_left (||) false (List.map match_ip ips)
    then Lwt.return ()
    else Lwt.fail (Unix.Unix_error(Unix.EPERM, "bind", ""))

  module Mux = Forwarder.Multiplexer.Make(Connector)

  (* Since we only need one connection to the port forwarding service,
     connect on demand and cache it. *)
  let get_mux =
    let mux = ref None in
    let m = Lwt_mutex.create () in
    fun () ->
      Lwt_mutex.with_lock m
        (fun () ->
          (* If there is a multiplexer but it is broken, reconnect *)
          begin match !mux with
          | None -> Lwt.return_unit
          | Some m ->
            if not(Mux.is_running m) then begin
              Log.err (fun f -> f "Multiplexer has shutdown, reconnecting");
              mux := None;
              Mux.disconnect m
            end else Lwt.return_unit
          end >>= fun () ->
          match !mux with
          | None ->
            Connector.connect ()
            >>= fun remote ->
            let mux' = Mux.connect remote "port-forwarding"
              (fun flow destination ->
                Log.err (fun f -> f "Unexpected connection from %s via port multiplexer" (Forwarder.Frame.Destination.to_string destination));
                Mux.Channel.close flow
              ) in
            mux := Some mux';
            Lwt.return mux'
          | Some m -> Lwt.return m
        )

  let open_channel destination =
    get_mux ()
    >>= fun mux ->
    Mux.Channel.connect mux destination

  let start_tcp_proxy clock description remote_port server =
    let module Proxy = Mirage_flow_lwt.Proxy(Clock)(Mux.Channel)(Socket.Stream.Tcp) in
    Socket.Stream.Tcp.listen server (fun local ->
        open_channel remote_port
        >>= fun remote ->
        Lwt.finalize (fun () ->
            Log.debug (fun f -> f "%s: connected" description);
            Proxy.proxy clock remote local  >|= function
            | Error e ->
              Log.err (fun f ->
                  f "%s proxy failed with %a" description Proxy.pp_error e)
            | Ok (l_stats, r_stats) ->
              Log.debug (fun f ->
                  f "%s completed: l2r = %a; r2l = %a" description
                    Mirage_flow.pp_stats l_stats
                    Mirage_flow.pp_stats r_stats
                )
          ) (fun () ->
            Mux.Channel.close remote
          )
      );
    Lwt.return ()

  let start_unix_proxy clock description remote_port server =
    let module Proxy = Mirage_flow_lwt.Proxy(Clock)(Mux.Channel)(Socket.Stream.Unix) in
    Socket.Stream.Unix.listen server (fun local ->
        open_channel remote_port
        >>= fun remote ->
        Lwt.finalize (fun () ->
            Log.debug (fun f -> f "%s: connected" description);
            Proxy.proxy clock remote local  >|= function
            | Error e ->
              Log.err (fun f ->
                  f "%s proxy failed with %a" description Proxy.pp_error e)
            | Ok (l_stats, r_stats) ->
              Log.debug (fun f ->
                  f "%s completed: l2r = %a; r2l = %a" description
                    Mirage_flow.pp_stats l_stats
                    Mirage_flow.pp_stats r_stats
                )
          ) (fun () ->
            Mux.Channel.close remote
          )
      );
    Lwt.return ()

  let conn_read flow buf =
    Mux.Channel.read_into flow buf >>= function
    | Ok `Eof       -> Lwt.fail End_of_file
    | Error e       -> Fmt.kstrf Lwt.fail_with "%a" Mux.Channel.pp_error e
    | Ok (`Data ()) -> Lwt.return ()

  let conn_write flow buf =
    Mux.Channel.write flow buf >>= function
    | Error `Closed -> Lwt.fail End_of_file
    | Error e       -> Fmt.kstrf Lwt.fail_with "%a" Mux.Channel.pp_write_error e
    | Ok ()         -> Lwt.return ()

  let start_udp_proxy description remote_port server =
    let from_internet_buffer = Cstruct.create Constants.max_udp_length in
    (* We write to the internet using the from_vsock_buffer *)
    let from_vsock_buffer =
      Cstruct.create (Constants.max_udp_length + Forwarder.Frame.Udp.max_sizeof)
    in
    let handle fd =
      (* Construct the vsock header in a separate buffer but write the payload
         directly from the from_internet_buffer *)
      let write_header_buffer = Cstruct.create Forwarder.Frame.Udp.max_sizeof in
      let write v buf (ip, port) =
        let udp = Forwarder.Frame.Udp.({
            ip; port;
            payload_length = Cstruct.len buf;
        }) in
        let header = Forwarder.Frame.Udp.write_header udp write_header_buffer in
        conn_write v header >>= fun () ->
        conn_write v buf
      in
      (* Read the vsock header and payload into the same buffer, and write it
         to the internet from there. *)
      let read v =
        conn_read v (Cstruct.sub from_vsock_buffer 0 2) >>= fun () ->
        let frame_length = Cstruct.LE.get_uint16 from_vsock_buffer 0 in
        if frame_length > (Cstruct.len from_vsock_buffer) then begin
          Log.err (fun f ->
              f "UDP encapsulated frame length is %d but buffer has length %d: \
                 dropping" frame_length (Cstruct.len from_vsock_buffer));
          Lwt.return None
        end else begin
          let rest = Cstruct.sub from_vsock_buffer 2 (frame_length - 2) in
          conn_read v rest >|= fun () ->
          let udp, payload = Forwarder.Frame.Udp.read from_vsock_buffer in
          Some (payload, (udp.Forwarder.Frame.Udp.ip, udp.Forwarder.Frame.Udp.port))
        end
      in
      let rec from_internet v =
        Lwt.catch (fun () ->
            Socket.Datagram.Udp.recvfrom fd from_internet_buffer
            >>= fun (len, address) ->
            write v (Cstruct.sub from_internet_buffer 0 len) address
            >>= fun () ->
            Lwt.return true
          ) (function
          | Unix.Unix_error(Unix.EBADF, _, _) -> Lwt.return false
          | e ->
            Log.err (fun f ->
                f "%s: shutting down recvfrom thread: %a" description Fmt.exn e);
            Lwt.return false)
        >>= function
        | true -> from_internet v
        | false -> Lwt.return ()
      in
      let rec from_vsock v =
        Lwt.catch (fun () ->
            read v >>= function
            | None                -> Lwt.return false
            | Some (buf, address) ->
              Socket.Datagram.Udp.sendto fd address buf >|= fun () ->
              true
          ) (fun e ->
            Log.debug (fun f ->
                f "%s: shutting down from vsock thread: %a"
                  description Fmt.exn e);
            Lwt.return false
          ) >>= function
        | true -> from_vsock v
        | false -> Lwt.return ()
      in
      Log.debug (fun f ->
          f "%s: connecting to vsock port %s" description
            (Port.to_string remote_port));

      open_channel remote_port
      >>= fun remote ->
      Lwt.finalize (fun () ->
          Log.debug (fun f ->
              f "%s: connected to vsock port %s" description
                (Port.to_string remote_port));
          (* FIXME(samoht): why ignoring that thread here? *)
          let _ = from_vsock remote in
          from_internet remote
        ) (fun () -> Mux.Channel.close remote)
    in
    Lwt.async (fun () ->
        log_exception_continue "udp handle" (fun () -> handle server));
    Lwt.return ()

  let start state t =
    match t.local with
    | `Tcp (local_ip, local_port) ->
      let description =
        Fmt.strf "forwarding from tcp:%a:%d" Ipaddr.pp local_ip local_port
      in
      Lwt.catch (fun () ->
          check_bind_allowed local_ip  >>= fun () ->
          Socket.Stream.Tcp.bind ~description (local_ip, local_port)
          >>= fun server ->
          t.server <- Some (`Tcp server);
          (* Resolve the local port yet (the fds are already bound) *)
          Socket.Stream.Tcp.getsockname server
          >>= fun (_, bound_port) ->
          t.local <- ( match t.local with
            | `Tcp (ip, 0) -> `Tcp (ip, bound_port)
            | _ -> t.local );
          start_tcp_proxy state (to_string t) t.remote_port server
          >|= fun () ->
          Ok t
        ) (function
        | Unix.Unix_error(Unix.EADDRINUSE, _, _) ->
          errorf' "Bind for %a:%d failed: port is already allocated"
            Ipaddr.pp local_ip local_port
        | Unix.Unix_error(Unix.EADDRNOTAVAIL, _, _) ->
          errorf' "listen tcp %a:%d: bind: cannot assign requested address"
            Ipaddr.pp local_ip local_port
        | Unix.Unix_error(Unix.EPERM, _, _) ->
          errorf' "Bind for %a:%d failed: permission denied"
            Ipaddr.pp local_ip local_port
        | e ->
          errorf' "Bind for %a:%d: unexpected error %a" Ipaddr.pp local_ip
            local_port Fmt.exn e
        )
    | `Udp (local_ip, local_port) ->
      let description =
        Fmt.strf "forwarding from udp:%a:%d" Ipaddr.pp local_ip local_port
      in
      Lwt.catch (fun () ->
          check_bind_allowed local_ip >>= fun () ->
          Socket.Datagram.Udp.bind ~description (local_ip, local_port)
          >>= fun server ->
          t.server <- Some (`Udp server);
          (* Resolve the local port yet (the fds are already bound) *)
          Socket.Datagram.Udp.getsockname server
          >>= fun (_, bound_port) ->
          t.local <- ( match t.local with
            | `Udp (ip, 0) -> `Udp (ip, bound_port)
            | _ -> t.local );
          start_udp_proxy (to_string t) t.remote_port server
          >|= fun () ->
          Ok t
        ) (function
        | Unix.Unix_error(Unix.EADDRINUSE, _, _) ->
          errorf' "Bind for %a:%d failed: port is already allocated"
            Ipaddr.pp local_ip local_port
        | Unix.Unix_error(Unix.EADDRNOTAVAIL, _, _) ->
          errorf' "listen udp %a:%d: bind: cannot assign requested address"
            Ipaddr.pp local_ip local_port
        | Unix.Unix_error(Unix.EPERM, _, _) ->
          errorf' "Bind for %a:%d failed: permission denied"
            Ipaddr.pp local_ip local_port
        | e ->
          errorf' "Bind for %a:%d: unexpected error %a" Ipaddr.pp local_ip
            local_port Fmt.exn e
        )
    | `Unix path ->
      let description =
        Fmt.strf "forwarding from unix:%s" path
      in
      Lwt.catch (fun () ->
          Socket.Stream.Unix.bind ~description path
          >>= fun server ->
          t.server <- Some (`Unix server);
          start_unix_proxy state (to_string t) t.remote_port server
          >|= fun () ->
          Ok t
        ) (function
        | Unix.Unix_error(Unix.EADDRINUSE, _, _) ->
          errorf' "Bind for %s failed: port is already allocated" path
        | Unix.Unix_error(Unix.EADDRNOTAVAIL, _, _) ->
          errorf' "listen %s: bind: cannot assign requested address" path
        | Unix.Unix_error(Unix.EPERM, _, _) ->
          errorf' "Bind for %s failed: permission denied" path
        | e ->
          errorf' "Bind for %s: unexpected error %a" path
            Fmt.exn e
        )

  let stop t =
    Log.debug (fun f -> f "%s: closing listening socket" (to_string t));
    match t.server with
    | Some (`Tcp s) -> Socket.Stream.Tcp.shutdown s
    | Some (`Udp s) -> Socket.Datagram.Udp.shutdown s
    | Some (`Unix s) -> Socket.Stream.Unix.shutdown s
    | None -> Lwt.return_unit

  let of_string x =
    match Stringext.split ~on:':' ~max:6 x with
    | [ proto1; ip1; port1; proto2; ip2; port2 ] ->
      begin
        match
          Port.of_string (proto1 ^ ":" ^ ip1 ^ ":" ^ port1),
          Port.of_string (proto2 ^ ":" ^ ip2 ^ ":" ^ port2)
        with
        | Error x, _ -> Error x
        | _, Error x -> Error x
        | Ok local, Ok remote_port ->
          Ok { local; remote_port; server = None }
      end
    | [ "unix"; path1; "unix"; path2 ] ->
      begin
        match
          Port.of_string ("unix:" ^ path1),
          Port.of_string ("unix:" ^ path2)
        with
        | Error x, _ -> Error x
        | _, Error x -> Error x
        | Ok local, Ok remote_port ->
          Ok { local; remote_port; server = None }
      end
    | _ ->
      errorf "Failed to parse request [%s], expected %s" x description_of_format
end

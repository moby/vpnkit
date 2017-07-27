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
       Log.err (fun f -> f "%s: caught %a" description Fmt.exn e);
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

module Int16 = struct
  type t = int
end

module Port = struct
  type t = [
    | `Tcp of Ipaddr.t * Int16.t
    | `Udp of Ipaddr.t * Int16.t
  ]

  let to_string = function
  | `Tcp (addr, port) -> Fmt.strf "tcp:%a:%d" Ipaddr.pp_hum addr port
  | `Udp (addr, port) -> Fmt.strf "udp:%a:%d" Ipaddr.pp_hum addr port

  let of_string x =
    try
      match Stringext.split ~on:':' x with
      | [ proto; ip; port ] ->
        let port = int_of_string port in
        begin match String.lowercase_ascii proto with
        | "tcp" -> Ok (`Tcp (Ipaddr.of_string_exn ip, port))
        | "udp" -> Ok (`Udp (Ipaddr.of_string_exn ip, port))
        | _ -> errorf "unknown protocol: should be tcp or udp"
        end
      | _ -> errorf "port should be of the form proto:IP:port"
    with
    | _ -> errorf "port is not a proto:IP:port: '%s'" x

end

module Make
    (Clock: Mirage_clock_lwt.MCLOCK)
    (Connector: Sig.Connector)
    (Socket: Sig.SOCKETS) =
struct

  type server = [
    | `Tcp of Socket.Stream.Tcp.server
    | `Udp of Socket.Datagram.Udp.server
  ]

  type t = {
    mutable local: Port.t;
    remote_port: Port.t;
    mutable server: server option;
  }

  type key = Port.t

  let get_key t = t.local

  type clock = Clock.t
  type context = string

  let to_string t =
    Fmt.strf "%s:%s" (Port.to_string t.local) (Port.to_string t.remote_port)

  let description_of_format =
    "'<tcp|udp>:local ip:local port:remote vchan port'"

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

  (* Given a connection to the port forwarding service, write the
     header which describes the container IP and port we wish to
     connect to. *)
  let write_forwarding_header description remote remote_port =
    (* Matches the Go definition *)
    let proto, ip, port = match remote_port with
    | `Tcp(Ipaddr.V4 ip, port) -> 1, Ipaddr.V4.to_bytes ip, port
    | `Tcp(Ipaddr.V6 ip, port) -> 1, Ipaddr.V6.to_bytes ip, port
    | `Udp(Ipaddr.V4 ip, port) -> 2, Ipaddr.V4.to_bytes ip, port
    | `Udp(Ipaddr.V6 ip, port) -> 2, Ipaddr.V6.to_bytes ip, port
    in
    let header = Cstruct.create (1 + 2 + 4 + 2) in
    Cstruct.set_uint8 header 0 proto;
    Cstruct.LE.set_uint16 header 1 4;
    Cstruct.blit_from_string ip 0 header 3 4;
    Cstruct.LE.set_uint16 header 7 port;
    (* Write the header, we should be connected to the container port *)
    Connector.write remote header >>= function
    | Ok  () -> Lwt.return_unit
    | Error `Closed ->
      let msg = Fmt.strf "%s: EOF writing forwarding header" description in
      Log.err (fun f -> f "%s" msg);
      Lwt.fail (Failure msg)
    | Error e ->
      let msg =
        Fmt.strf "%s: failed to write forwarding header: %a" description
          Connector.pp_write_error e
      in
      Log.err (fun f -> f "%s" msg);
      Lwt.fail (Failure msg)

  module Proxy = Mirage_flow_lwt.Proxy(Clock)(Connector)(Socket.Stream.Tcp)

  let start_tcp_proxy clock description vsock_path_var remote_port server =
    Socket.Stream.Tcp.listen server (fun local ->
        Active_list.Var.read vsock_path_var >>= fun _vsock_path ->
        Connector.connect () >>= fun remote ->
        Lwt.finalize (fun () ->
            write_forwarding_header description remote remote_port
            >>= fun () ->
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
            Connector.close remote
          )
      );
    Lwt.return ()

  let max_vsock_header_length = 1024

  let conn_read flow buf =
    Connector.read_into flow buf >>= function
    | Ok `Eof       -> Lwt.fail End_of_file
    | Error e       -> Fmt.kstrf Lwt.fail_with "%a" Connector.pp_error e
    | Ok (`Data ()) -> Lwt.return ()

  let conn_write flow buf =
    Connector.write flow buf >>= function
    | Error `Closed -> Lwt.fail End_of_file
    | Error e       -> Fmt.kstrf Lwt.fail_with "%a" Connector.pp_write_error e
    | Ok ()         -> Lwt.return ()

  let start_udp_proxy description vsock_path_var remote_port server =
    let from_internet_buffer = Cstruct.create Constants.max_udp_length in
    (* We write to the internet using the from_vsock_buffer *)
    let from_vsock_buffer =
      Cstruct.create (Constants.max_udp_length + max_vsock_header_length)
    in
    let handle fd =
      Active_list.Var.read vsock_path_var >>= fun _vsock_path ->
      (* Construct the vsock header in a separate buffer but write the payload
         directly from the from_internet_buffer *)
      let write_header_buffer = Cstruct.create max_vsock_header_length in
      let write v buf (ip, port) =
        (* Leave space for a uint16 frame length *)
        let rest = Cstruct.shift write_header_buffer 2 in
        (* uint16 IP address length *)
        let ip_bytes =
          match ip with
          | Ipaddr.V4 ipv4 -> Ipaddr.V4.to_bytes ipv4
          | Ipaddr.V6 ipv6 -> Ipaddr.V6.to_bytes ipv6
        in
        let ip_bytes_len = String.length ip_bytes in
        Cstruct.LE.set_uint16 rest 0 ip_bytes_len;
        let rest = Cstruct.shift rest 2 in
        (* IP address bytes *)
        Cstruct.blit_from_string ip_bytes 0 rest 0 ip_bytes_len;
        let rest = Cstruct.shift rest ip_bytes_len in
        (* uint16 Port *)
        Cstruct.LE.set_uint16 rest 0 port;
        let rest = Cstruct.shift rest 2 in
        (* uint16 Zone length *)
        Cstruct.LE.set_uint16 rest 0 0;
        let rest = Cstruct.shift rest 2 in
        (* Zone string *)
        (* uint16 payload length *)
        Cstruct.LE.set_uint16 rest 0 (Cstruct.len buf);
        let rest = Cstruct.shift rest 2 in
        let header_len = rest.Cstruct.off - write_header_buffer.Cstruct.off in
        let frame_len = header_len + (Cstruct.len buf) in
        let header = Cstruct.sub write_header_buffer 0 header_len in
        (* Add an overall frame length at the start *)
        Cstruct.LE.set_uint16 header 0 frame_len;
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
          (* uint16 IP address length *)
          let ip_bytes_len = Cstruct.LE.get_uint16 rest 0 in
          (* IP address bytes *)
          let ip_bytes_string = Cstruct.(to_string (sub rest 2 ip_bytes_len)) in
          let rest = Cstruct.shift rest (2 + ip_bytes_len) in
          let ip =
            let open Ipaddr in
            if String.length ip_bytes_string = 4
            then V4 (V4.of_bytes_exn ip_bytes_string)
            else V6 (Ipaddr.V6.of_bytes_exn ip_bytes_string)
          in
          (* uint16 Port *)
          let port = Cstruct.LE.get_uint16 rest 0 in
          let rest = Cstruct.shift rest 2 in
          (* uint16 Zone length *)
          let zone_length = Cstruct.LE.get_uint16 rest 0 in
          let rest = Cstruct.shift rest (2 + zone_length) in
          (* uint16 payload length *)
          let payload_length = Cstruct.LE.get_uint16 rest 0 in
          (* payload *)
          let payload = Cstruct.sub rest 2 payload_length in
          Some (payload, (ip, port))
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
          | Unix.Unix_error(e, _, _) when Uwt.of_unix_error e = Uwt.ECANCELED ->
            Lwt.return false
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
      Connector.connect () >>= fun v ->
      Lwt.finalize (fun () ->
          write_forwarding_header description v remote_port
          >>= fun () ->
          Log.debug (fun f ->
              f "%s: connected to vsock port %s" description
                (Port.to_string remote_port));
          (* FIXME(samoht): why ignoring that thread here? *)
          let _ = from_vsock v in
          from_internet v
        ) (fun () -> Connector.close v)
    in
    Lwt.async (fun () ->
        log_exception_continue "udp handle" (fun () -> handle server));
    Lwt.return ()

  let start state vsock_path_var t =
    match t.local with
    | `Tcp (local_ip, local_port)  ->
      let description =
        Fmt.strf "forwarding from tcp:%a:%d" Ipaddr.pp_hum local_ip local_port
      in
      Lwt.catch (fun () ->
          check_bind_allowed local_ip  >>= fun () ->
          Socket.Stream.Tcp.bind ~description (local_ip, local_port)
          >>= fun server ->
          t.server <- Some (`Tcp server);
          (* Resolve the local port yet (the fds are already bound) *)
          t.local <- ( match t.local with
            | `Tcp (local_ip, 0) ->
              let _, port = Socket.Stream.Tcp.getsockname server in
              `Tcp (local_ip, port)
            | _ ->
              t.local );
          start_tcp_proxy state (to_string t) vsock_path_var t.remote_port server
          >|= fun () ->
          Ok t
        ) (function
        | Unix.Unix_error(Unix.EADDRINUSE, _, _) ->
          errorf' "Bind for %a:%d failed: port is already allocated"
            Ipaddr.pp_hum local_ip local_port
        | Unix.Unix_error(Unix.EADDRNOTAVAIL, _, _) ->
          errorf' "listen tcp %a:%d: bind: cannot assign requested address"
            Ipaddr.pp_hum local_ip local_port
        | Unix.Unix_error(Unix.EPERM, _, _) ->
          errorf' "Bind for %a:%d failed: permission denied"
            Ipaddr.pp_hum local_ip local_port
        | e ->
          errorf' "Bind for %a:%d: unexpected error %a" Ipaddr.pp_hum local_ip
            local_port Fmt.exn e
        )
    | `Udp (local_ip, local_port) ->
      let description =
        Fmt.strf "forwarding from udp:%a:%d" Ipaddr.pp_hum local_ip local_port
      in
      Lwt.catch (fun () ->
          check_bind_allowed local_ip >>= fun () ->
          Socket.Datagram.Udp.bind ~description (local_ip, local_port)
          >>= fun server ->
          t.server <- Some (`Udp server);
          start_udp_proxy (to_string t) vsock_path_var t.remote_port server
          >|= fun () ->
          Ok t
        ) (function
        | Unix.Unix_error(Unix.EADDRINUSE, _, _) ->
          errorf' "Bind for %a:%d failed: port is already allocated"
            Ipaddr.pp_hum local_ip local_port
        | Unix.Unix_error(Unix.EADDRNOTAVAIL, _, _) ->
          errorf' "listen udp %a:%d: bind: cannot assign requested address"
            Ipaddr.pp_hum local_ip local_port
        | Unix.Unix_error(Unix.EPERM, _, _) ->
          errorf' "Bind for %a:%d failed: permission denied"
            Ipaddr.pp_hum local_ip local_port
        | e ->
          errorf' "Bind for %a:%d: unexpected error %a" Ipaddr.pp_hum local_ip
            local_port Fmt.exn e
        )

  let stop t =
    Log.debug (fun f -> f "%s: closing listening socket" (to_string t));
    match t.server with
    | Some (`Tcp s) -> Socket.Stream.Tcp.shutdown s
    | Some (`Udp s) -> Socket.Datagram.Udp.shutdown s
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
    | _ ->
      errorf "Failed to parse request [%s], expected %s" x description_of_format
end

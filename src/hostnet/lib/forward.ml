open Lwt.Infix

let src =
  let src = Logs.Src.create "port forward" ~doc:"forward local ports to the VM" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let log_exception_continue description f =
  Lwt.catch
    (fun () -> f ())
    (fun e ->
       Log.err (fun f -> f "%s: caught %s" description (Printexc.to_string e));
       Lwt.return ()
    )

let allowed_addresses = ref None

let set_allowed_addresses ips =
  Log.info (fun f -> f "allowing binds to %s" (match ips with
    | None -> "any IP addresses"
    | Some ips -> String.concat ", " (List.map Ipaddr.to_string ips)
  ));
  allowed_addresses := ips

module Result = struct
  include Result
  let return x = Ok x
  let errorf fmt = Printf.ksprintf (fun s -> Error (`Msg s)) fmt
end

module Int16 = struct
  module M = struct
    type t = int
    let compare (a: t) (b: t) = Pervasives.compare a b
  end
  include M
  module Map = Map.Make(M)
  module Set = Set.Make(M)
end

module Port = struct
  module M = struct
    type t = [
      | `Tcp of Ipaddr.V4.t * Int16.t
      | `Udp of Ipaddr.V4.t * Int16.t
    ]
    let compare = compare
  end
  include M
  module Map = Map.Make(M)
  module Set = Set.Make(M)

  let to_string = function
    | `Tcp (addr, port) -> Printf.sprintf "tcp:%s:%d" (Ipaddr.V4.to_string addr) port
    | `Udp (addr, port) -> Printf.sprintf "udp:%s:%d" (Ipaddr.V4.to_string addr) port

  let of_string x =
    try
        match Stringext.split ~on:':' x with
        | [ proto; ip; port ] ->
          let ip = Ipaddr.V4.of_string_exn ip in
          let port = int_of_string port in
          begin match String.lowercase proto with
            | "tcp" -> Result.return (`Tcp (ip, port))
            | "udp" -> Result.return (`Udp (ip, port))
            | _ -> Result.errorf "unknown protocol: should be tcp or udp"
          end
        | _ ->
        Result.errorf "port should be of the form proto:IP:port"
    with
      | _ -> Result.Error (`Msg (Printf.sprintf "port is not a proto:IP:port: '%s'" x))

end

module Make(Connector: Sig.Connector with type port = Port.t)(Binder: Sig.Binder) = struct
type t = {
  local: Port.t;
  remote_port: Port.t;
  mutable fd: Lwt_unix.file_descr option;
}

type key = Port.t

let get_key t = t.local

module Map = Port.Map

type context = string

let to_string t = Printf.sprintf "%s:%s" (Port.to_string t.local) (Port.to_string t.remote_port)

let description_of_format = "'<tcp|udp>:local ip:local port:remote vchan port'"

let finally f g =
  Lwt.catch (fun () ->
    f ()
    >>= fun r ->
    g ()
    >>= fun () ->
    Lwt.return r
  ) (fun e ->
    g ()
    >>= fun () ->
    Lwt.fail e
  )

let check_bind_allowed ip = match !allowed_addresses with
  | None -> Lwt.return () (* no restriction *)
  | Some ips ->
    let match_ipv4 = function
      | Ipaddr.V6 _ -> false
      | Ipaddr.V4 x when x = Ipaddr.V4.any -> true
      | Ipaddr.V4 x -> x = ip in
    if List.fold_left (||) false (List.map match_ipv4 ips)
    then Lwt.return ()
    else Lwt.fail (Unix.Unix_error(Unix.EPERM, "bind", ""))


let bind local =
  match local with
  | `Tcp (local_ip, local_port)  ->
    check_bind_allowed local_ip
    >>= fun () ->
    Binder.bind local_ip local_port true
  | `Udp (local_ip, local_port) ->
    check_bind_allowed local_ip
    >>= fun () ->
    Binder.bind local_ip local_port false

let start_tcp_proxy vsock_path_var _local_ip _local_port fd t =
  (* On failure here, we must close the fd *)
  Lwt.catch
    (fun () ->
       Lwt_unix.listen fd 5;
       match t.local, Lwt_unix.getsockname fd with
       | `Tcp (local_ip, _), Lwt_unix.ADDR_INET(_, local_port) ->
         let t = { t with local = `Tcp(local_ip, local_port) } in
         Lwt.return (Result.Ok (t, fd))
       | _ ->
         Lwt.return (Result.Error (`Msg "failed to query local port"))
    ) (fun e ->
        Lwt_unix.close fd
        >>= fun () ->
        Lwt.return (Result.Error (`Msg (Printf.sprintf "failed to listen: %s" (Printexc.to_string e))))
      )
  >>= function
  | Result.Error e -> Lwt.return (Result.Error e)
  | Result.Ok (t, fd) ->
    (* The `Forward.stop` function is in charge of closing the fd *)
    let t = { t with fd = Some fd } in
    let description = to_string t in
    let rec loop () =
      Lwt.catch (fun () ->
          Lwt_unix.accept fd
          >>= fun (local_fd, _) ->
          Lwt.return (Some local_fd)
        ) (function
          | Unix.Unix_error(Unix.EBADF, _, _) -> Lwt.return None
          | e ->
            Log.err (fun f -> f "%s: failed to accept: %s" description (Printexc.to_string e));
            Lwt.return None
        )
      >>= function
      | None ->
        Log.debug (fun f -> f "%s: listening thread shutting down" description);
        Lwt.return ()
      | Some local_fd ->
        let local = Socket.Stream.of_fd ~description local_fd in
        Active_list.Var.read vsock_path_var
        >>= fun _vsock_path ->
        let proxy () =
          finally (fun () ->
            Connector.connect t.remote_port
            >>= fun remote ->
            finally (fun () ->
              (* proxy between local and remote *)
              Log.debug (fun f -> f "%s: connected" description);
              Mirage_flow.proxy (module Clock) (module Connector) remote (module Socket.Stream) local ()
              >>= function
              | `Error (`Msg m) ->
                Log.err (fun f -> f "%s proxy failed with %s" description m);
                Lwt.return ()
              | `Ok (l_stats, r_stats) ->
                Log.debug (fun f ->
                    f "%s completed: l2r = %s; r2l = %s" description
                      (Mirage_flow.CopyStats.to_string l_stats) (Mirage_flow.CopyStats.to_string r_stats)
                  );
                Lwt.return ()
            ) (fun () ->
              Connector.close remote
            )
          ) (fun () ->
            Socket.Stream.close local
            >>= fun () ->
            Lwt.return ()
          )
        in
        Lwt.async (fun () -> log_exception_continue (description ^ " proxy") proxy);
        loop () in
    Lwt.async loop;
    Lwt.return (Result.Ok t)

let max_udp_length = 2048 (* > 1500 the MTU of our link + header *)

let max_vsock_header_length = 1024

let conn_read flow buf =
  let open Lwt.Infix in
  Connector.read_into flow buf
  >>= function
  | `Eof -> Lwt.fail End_of_file
  | `Error e -> Lwt.fail (Failure (Connector.error_message e))
  | `Ok () -> Lwt.return ()

let conn_write flow buf =
  let open Lwt.Infix in
  Connector.write flow buf
  >>= function
  | `Eof -> Lwt.fail End_of_file
  | `Error e -> Lwt.fail (Failure (Connector.error_message e))
  | `Ok () -> Lwt.return ()

let start_udp_proxy vsock_path_var _local_ip _local_port fd t =
  let open Lwt.Infix in
  let description = to_string t in
  let from_internet_string = Bytes.make max_udp_length '\000' in
  let from_internet_buffer = Cstruct.create max_udp_length in
  (* We write to the internet using the from_vsock_buffer *)
  let from_vsock_string = Bytes.make max_udp_length '\000' in
  let from_vsock_buffer = Cstruct.create max_udp_length in
  let _ =
    Active_list.Var.read vsock_path_var
    >>= fun _vsock_path ->
    Log.debug (fun f -> f "%s: connecting to vsock port %s" description (Port.to_string t.remote_port));
    Connector.connect t.remote_port
    >>= fun v ->
    Log.debug (fun f -> f "%s: connected to vsock port %s" description (Port.to_string t.remote_port));
    (* Construct the vsock header in a separate buffer but write the payload
       directly from the from_internet_buffer *)
    let write_header_buffer = Cstruct.create max_vsock_header_length in
    let write buf sockaddr = match sockaddr with
      | Unix.ADDR_UNIX _ ->
        Log.err (fun f -> f "%s: dropping UDP packet from unix domain socket" description);
        Lwt.return ()
      | Unix.ADDR_INET (ip, port) ->
        (* Leave space for a uint16 frame length *)
        let rest = Cstruct.shift write_header_buffer 2 in
        (* uint16 IP address length *)
        let ip_bytes =
          match Ipaddr.of_string @@ Unix.string_of_inet_addr ip with
          | Some Ipaddr.V4 ipv4 -> Ipaddr.V4.to_bytes ipv4
          | Some Ipaddr.V6 ipv6 -> Ipaddr.V6.to_bytes ipv6
          | None ->
            Log.err (fun f -> f "%s: Ipaddr.of_string failed to parse IP %s" description (Unix.string_of_inet_addr ip));
            failwith "Failed to parse IP" in
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
        conn_write v header
        >>= fun () ->
        conn_write v buf in
    (* Read the vsock header and payload into the same buffer, and write it
       to the internet from there. *)
    let read () =
      conn_read v (Cstruct.sub from_vsock_buffer 0 2)
      >>= fun () ->
      let frame_length = Cstruct.LE.get_uint16 from_vsock_buffer 0 in
      let rest = Cstruct.sub from_vsock_buffer 2 (frame_length - 2) in
      conn_read v rest
      >>= fun () ->
      (* uint16 IP address length *)
      let ip_bytes_len = Cstruct.LE.get_uint16 rest 0 in
      (* IP address bytes *)
      let ip_bytes_string = Cstruct.(to_string (sub rest 2 ip_bytes_len)) in
      let rest = Cstruct.shift rest (2 + ip_bytes_len) in
      let ip =
        Unix.inet_addr_of_string (
          if String.length ip_bytes_string = 4
          then Ipaddr.V4.to_string (Ipaddr.V4.of_bytes_exn ip_bytes_string)
          else Ipaddr.V6.to_string (Ipaddr.V6.of_bytes_exn ip_bytes_string)
        ) in
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
      Lwt.return (payload.Cstruct.off, payload_length, Unix.ADDR_INET(ip, port)) in
    let rec from_internet () =
      Lwt.catch (fun () ->
        Lwt_unix.recvfrom fd from_internet_string 0 (String.length from_internet_string) []
        >>= fun (len, sockaddr) ->
        Cstruct.blit_from_string from_internet_string 0 from_internet_buffer 0 len;
        write (Cstruct.sub from_internet_buffer 0 len) sockaddr
        >>= fun () ->
        Lwt.return true
      ) (function
        | Unix.Unix_error(Unix.EBADF, _, _) -> Lwt.return false
        | e ->
          Log.err (fun f -> f "%s: shutting down recvfrom thread: %s" description (Printexc.to_string e));
          Lwt.return false
      )
      >>= function
      | true -> from_internet ()
      | false -> Lwt.return () in
    let rec from_vsock () =
      Lwt.catch
        (fun () ->
          read ()
          >>= fun (ofs, len, sockaddr) ->
          (* Lwt on Win32 doesn't support Lwt_bytes.sendto *)
          Cstruct.blit_to_bytes from_vsock_buffer ofs from_vsock_string 0 len;
          Lwt_unix.sendto fd from_vsock_string 0 len [] sockaddr
          >>= fun _ ->
          Lwt.return true
        ) (fun e ->
          Log.debug (fun f -> f "%s: shutting down from vsock thread: %s" description (Printexc.to_string e));
          Lwt.return false
        ) >>= function
        | true -> from_vsock ()
        | false -> Lwt.return () in
    let _ = from_vsock () in
    from_internet ()
    >>= fun () ->
    Connector.close v in
  Lwt.return (Result.Ok t)

let start vsock_path_var t =
  bind t.local
  >>= function
  | Result.Error (`Msg m) ->
    Lwt.return (Result.Error (`Msg m))
  | Result.Ok fd ->
  let t = { t with fd = Some fd } in
  match t.local with
  | `Tcp (local_ip, local_port) ->
    start_tcp_proxy vsock_path_var local_ip local_port fd t
  | `Udp (local_ip, local_port) ->
    start_udp_proxy vsock_path_var local_ip local_port fd t

let stop t = match t.fd with
  | None -> Lwt.return ()
  | Some fd ->
    t.fd <- None;
    Log.debug (fun f -> f "%s: closing listening socket" (to_string t));
    Lwt_unix.close fd

let of_string x =
  match Stringext.split ~on:':' ~max:6 x with
  | [ proto1; ip1; port1; proto2; ip2; port2 ] ->
    begin
      match
        Port.of_string (proto1 ^ ":" ^ ip1 ^ ":" ^ port1),
        Port.of_string (proto2 ^ ":" ^ ip2 ^ ":" ^ port2)
      with
      | Result.Error x, _ -> Result.Error x
      | _, Result.Error x -> Result.Error x
      | Result.Ok local, Result.Ok remote_port ->
        Result.Ok { local; remote_port; fd = None }
    end
  | _ ->
    Result.errorf "Failed to parse request [%s], expected %s" x description_of_format
end

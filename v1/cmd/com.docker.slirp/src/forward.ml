open Utils

let src =
  let src = Logs.Src.create "port forward" ~doc:"forward local ports to the VM" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let finally f g =
  let open Lwt.Infix in
  Lwt.catch (fun () -> f () >>= fun r -> g () >>= fun () -> Lwt.return r) (fun e -> g () >>= fun () -> Lwt.fail e)

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

module Port = struct
  module M = struct
    type t = int
    let compare (a: t) (b: t) = Pervasives.compare a b
  end
  include M
  module Map = Map.Make(M)
  module Set = Set.Make(M)
  let of_string x =
    try
      let x = int_of_string x in
      if x < 0 || x > 65535
      then Result.errorf "port out of range: 0 <= %d <= 65536" x
      else Result.return x
    with
    | _ -> Result.errorf "port is not an integer: '%s'" x
end

module VsockPort = struct
  type t = int32

  let of_string x =
    try
      Result.return @@ Int32.of_string ("0x" ^ x)
    with
    | _ -> Result.errorf "vchan port is not a hexadecimal int32: '%s'" x
end

module Local = struct
  module M = struct
    type t = [
      | `Tcp of Ipaddr.V4.t * Port.t
      | `Udp of Ipaddr.V4.t * Port.t
    ]
    let compare = compare
  end
  include M
  module Map = Map.Make(M)
  module Set = Set.Make(M)

  let to_string = function
    | `Tcp (addr, port) -> Printf.sprintf "tcp:%s:%d" (Ipaddr.V4.to_string addr) port
    | `Udp (addr, port) -> Printf.sprintf "udp:%s:%d" (Ipaddr.V4.to_string addr) port
end

type t = {
  local: Local.t;
  remote_port: VsockPort.t; (* vsock port *)
  mutable fd: Lwt_unix.file_descr option;
}

type key = Local.t

let get_key t = t.local

module Map = Local.Map

type context = string

let to_string t = Printf.sprintf "%s:%08lx" (Local.to_string t.local) t.remote_port

let description_of_format = "'<tcp|udp>:local ip:local port:remote vchan port' where the remote vchan port matches %08x"

let finally f g =
  let open Lwt.Infix in
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
  let open Lwt.Infix in
  match local with
  | `Tcp (local_ip, local_port) when local_port < 1024 ->
    check_bind_allowed local_ip
    >>= fun () ->
    let s = Lwt_unix.socket Lwt_unix.PF_UNIX Lwt_unix.SOCK_STREAM 0 in
    finally
      (fun () ->
        let open Lwt.Infix in
        Lwt_unix.connect s (Unix.ADDR_UNIX "/var/tmp/com.docker.vmnetd.socket")
        >>= fun () ->
        Vmnet.Client.of_fd s
        >>= fun r ->
        begin match r with
        | `Error (`Msg x) -> Lwt.return (Result.Error (`Msg x))
        | `Ok c ->
          Vmnet.Client.bind_ipv4 c (local_ip, local_port)
          >>= fun r ->
          begin match r with
          | `Ok fd ->
            Log.debug (fun f -> f "Received fd successfully");
            Lwt.return (Result.Ok fd)
          | `Error (`Msg x) ->
            Log.err (fun f -> f "Error binding to %s:%d: %s" (Ipaddr.V4.to_string local_ip) local_port x);
            Lwt.return (Result.Error (`Msg x))
          end
        end
      ) (fun () -> Lwt_unix.close s)
  | `Tcp (local_ip, local_port) ->
    check_bind_allowed local_ip
    >>= fun () ->
    let addr = Lwt_unix.ADDR_INET(Unix.inet_addr_of_string (Ipaddr.V4.to_string local_ip), local_port) in
    let fd = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_STREAM 0 in
    Lwt.catch
      (fun () -> Lwt_unix.bind fd addr; Lwt.return ())
      (fun e -> Lwt_unix.close fd >>= fun () -> Lwt.fail e)
    >>= fun () ->
    Lwt.return (Result.Ok fd)
  | `Udp (local_ip, local_port) ->
    check_bind_allowed local_ip
    >>= fun () ->
    let addr = Lwt_unix.ADDR_INET(Unix.inet_addr_of_string (Ipaddr.V4.to_string local_ip), local_port) in
    let fd = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_DGRAM 0 in
    Lwt.catch
      (fun () -> Lwt_unix.bind fd addr; Lwt.return ())
      (fun e -> Lwt_unix.close fd >>= fun () -> Lwt.fail e)
    >>= fun () ->
    Lwt.return (Result.Ok fd)

let start_tcp_proxy vsock_path_var local_ip local_port fd t =
  let open Lwt.Infix in
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
        (* Pretty-print the most common exception *)
        let message = match e with
        | Unix.Unix_error(Unix.EADDRINUSE, _, _) -> "address already in use"
        | e -> Printexc.to_string e in
        Lwt.return (Result.Error (`Msg (Printf.sprintf "failed to bind port: %s" message)))
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
        >>= fun vsock_path ->
        let proxy () =
          finally (fun () ->
            Osx_hyperkit.Vsock.connect ~path:vsock_path ~port:t.remote_port ()
            >>= fun v ->
            let remote = Socket.Stream.of_fd ~description v in
            finally (fun () ->
              (* proxy between local and remote *)
              Log.debug (fun f -> f "%s: connected" description);
              Mirage_flow.proxy (module Clock) (module Socket.Stream) remote (module Socket.Stream) local ()
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
              Socket.Stream.close remote
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

let start_udp_proxy vsock_path_var local_ip local_port fd t =
  let open Lwt.Infix in
  let description = to_string t in
  let from_internet_bytes = Lwt_bytes.create max_udp_length in
  let from_internet_buffer = Cstruct.of_bigarray from_internet_bytes in
  (* We write to the internet using the from_vsock_buffer *)
  let from_vsock_bytes = Lwt_bytes.create max_udp_length in
  let from_vsock_buffer = Cstruct.of_bigarray from_vsock_bytes in

  let _ =
    Active_list.Var.read vsock_path_var
    >>= fun vsock_path ->
    Osx_hyperkit.Vsock.connect ~path:vsock_path ~port:t.remote_port ()
    >>= fun v ->
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
        let header_len = rest.Cstruct.off - write_header_buffer.Cstruct.off + (Cstruct.len buf) in
        let header = Cstruct.sub write_header_buffer 0 header_len in
        (* Add an overall header length at the start *)
        Cstruct.LE.set_uint16 header 0 header_len;
        Lwt_cstruct.(complete (write v)) header
        >>= fun () ->
        Lwt_cstruct.(complete (write v)) buf in
    (* Read the vsock header and payload into the same buffer, and write it
       to the internet from there. *)
    let read () =
      Lwt_cstruct.(complete (read v)) (Cstruct.sub from_vsock_buffer 0 2)
      >>= fun () ->
      let frame_length = Cstruct.LE.get_uint16 from_vsock_buffer 0 in
      let rest = Cstruct.sub from_vsock_buffer 2 (frame_length - 2) in
      Lwt_cstruct.(complete (read v)) rest
      >>= fun () ->
      (* uint16 IP address length *)
      let ip_bytes_len = Cstruct.LE.get_uint16 rest 0 in
      (* IP address bytes *)
      let ip_bytes_string = Cstruct.(to_string (sub rest 2 ip_bytes_len)) in
      let rest = Cstruct.shift rest (2 + ip_bytes_len) in
      let ip =
        Unix.inet_addr_of_string (
          if String.length ip_bytes_string = 4
          then Ipaddr.V4.to_string @@ Ipaddr.V4.of_bytes_exn ip_bytes_string
          else Ipaddr.V6.to_string @@ Ipaddr.V6.of_bytes_exn ip_bytes_string
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
        Lwt_bytes.recvfrom fd from_internet_bytes 0 0 []
        >>= fun (len, sockaddr) ->
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
          Lwt_bytes.sendto fd from_vsock_bytes ofs len [] sockaddr
          >>= fun _ ->
          Lwt.return true
        ) (fun e ->
          Log.debug (fun f -> f "%s: shutting down from vsock thread: %s" description (Printexc.to_string e));
          Lwt.return false
        ) >>= function
        | true -> from_vsock ()
        | false -> Lwt.return () in
    let _ = from_internet () in
    let _ = from_vsock () in
    Lwt_unix.close v in
  Lwt.return (Result.Ok t)

let start vsock_path_var t =
  let open Lwt.Infix in
  bind t.local
  >>= function
  | Result.Error e -> Lwt.return (Result.Error e)
  | Result.Ok fd ->
  Lwt_unix.setsockopt fd Lwt_unix.SO_REUSEADDR true;
  let t = { t with fd = Some fd } in
  match t.local with
  | `Tcp (local_ip, local_port) ->
    start_tcp_proxy vsock_path_var local_ip local_port fd t
  | `Udp (local_ip, local_port) ->
    start_udp_proxy vsock_path_var local_ip local_port fd t

let stop t = match t.fd with
  | None -> Lwt.return ()
  | Some fd ->
    let open Lwt.Infix in
    t.fd <- None;
    Log.debug (fun f -> f "%s: closing listening socket" (to_string t));
    Lwt_unix.close fd

let of_string x =
  match (
    match Stringext.split ~on:':' x with
    | [ "tcp"; local_ip; local_port; remote_port ] ->
      let local_ip = Ipaddr.V4.of_string local_ip in
      let local_port = Port.of_string local_port in
      begin match local_ip, local_port with
      | Some ip, Result.Ok port ->
        Result.Ok (
          `Tcp (ip, port),
          VsockPort.of_string remote_port
        )
      | _, _ -> Result.Error (`Msg ("Failed to parse local IP and port: " ^ x))
      end
    | [ "udp"; local_ip; local_port; remote_port ] ->
      let local_ip = Ipaddr.V4.of_string local_ip in
      let local_port = Port.of_string local_port in
      begin match local_ip, local_port with
      | Some ip, Result.Ok port ->
        Result.Ok (
          `Udp (ip, port),
          VsockPort.of_string remote_port
        )
      | _, _ -> Result.Error (`Msg ("Failed to parse local IP and port: " ^ x))
      end
    | _ ->
      Result.Error (`Msg ("Failed to parse request, expected " ^ description_of_format))
  ) with
  | Result.Error x -> Result.Error x
  | Result.Ok (local, Result.Ok remote_port) ->
    Result.Ok { local; remote_port; fd = None  }
  | Result.Ok (_, Result.Error (`Msg m)) ->
    Result.Error (`Msg ("Failed to parse remote port: " ^ m))

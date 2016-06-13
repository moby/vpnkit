open Lwt.Infix

let src =
  let src = Logs.Src.create "port forward" ~doc:"forward local ports to the VM" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let common pf ty ip port =
  let addr = Lwt_unix.ADDR_INET(Unix.inet_addr_of_string @@ Ipaddr.to_string ip, port) in
  let fd = Lwt_unix.socket pf ty 0 in
  Lwt.catch
    (fun () ->
      Lwt_unix.setsockopt fd Lwt_unix.SO_REUSEADDR true;
      Lwt_unix.bind fd addr;
      Lwt.return fd
    ) (fun e ->
      Lwt_unix.close fd
      >>= fun () ->
      Lwt.fail e
    )

let bind local_ip local_port sock_stream =
  let ty = if sock_stream then Lwt_unix.SOCK_STREAM else Lwt_unix.SOCK_DGRAM in
  Lwt.catch
    (fun () ->
      common Lwt_unix.PF_INET ty Ipaddr.(V4 local_ip) local_port
      >>= fun fd ->
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
            common Lwt_unix.PF_INET6 ty Ipaddr.(V6 V6.localhost) local_port
            >>= fun fd ->
            Lwt.return [ fd ]
          end else begin
            Lwt.return []
          end
        ) (fun e ->
          Log.info (fun f -> f "ignoring failed bind to ::1:%d (%s)" local_port (Printexc.to_string e));
          Lwt.return []
        )
      >>= fun extra ->
      Lwt.return (Result.Ok (fd :: extra))
    ) (fun e ->
      (* Pretty-print the most common exception *)
      let message = match e with
      | Unix.Unix_error(Unix.EADDRINUSE, _, _) -> "address already in use"
      | e -> Printexc.to_string e in
        Lwt.return (Result.Error (`Msg (Printf.sprintf "Failed to bind %s %s:%d %s"
         (if sock_stream then "tcp" else "udp")
         (Ipaddr.V4.to_string local_ip) local_port message)))
      )

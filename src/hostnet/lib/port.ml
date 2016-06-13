open Lwt.Infix

let bind local_ip local_port sock_stream =
    let addr = Lwt_unix.ADDR_INET(Unix.inet_addr_of_string (Ipaddr.V4.to_string local_ip), local_port) in
    let fd = Lwt_unix.socket Lwt_unix.PF_INET (if sock_stream then Lwt_unix.SOCK_STREAM else Lwt_unix.SOCK_DGRAM) 0 in
    Lwt.catch
      (fun () ->
       Lwt_unix.setsockopt fd Lwt_unix.SO_REUSEADDR true;
       Lwt_unix.bind fd addr;
       Lwt.return (Result.Ok [ fd ]))
      (fun e ->
       Lwt_unix.close fd
       >>= fun () ->
        (* Pretty-print the most common exception *)
        let message = match e with
        | Unix.Unix_error(Unix.EADDRINUSE, _, _) -> "address already in use"
        | e -> Printexc.to_string e in
          Lwt.return (Result.Error (`Msg (Printf.sprintf "Failed to bind %s %s:%d %s"
         (if sock_stream then "tcp" else "udp")
         (Ipaddr.V4.to_string local_ip) local_port message)))
      )

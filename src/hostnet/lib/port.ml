let bind local_ip local_port sock_stream =
  let open Lwt.Infix in
    let addr = Lwt_unix.ADDR_INET(Unix.inet_addr_of_string (Ipaddr.V4.to_string local_ip), local_port) in
    let fd = Lwt_unix.socket Lwt_unix.PF_INET (if sock_stream then Lwt_unix.SOCK_STREAM else Lwt_unix.SOCK_DGRAM) 0 in
    Lwt.catch
      (fun () ->
       Lwt_unix.setsockopt fd Lwt_unix.SO_REUSEADDR true;
       Lwt_unix.bind fd addr;
       Lwt.return (Result.Ok fd))
      (fun e ->
       Lwt_unix.close fd
       >>= fun () ->
       Lwt.return (Result.Error (`Msg (Printf.sprintf "Failed to bind %s %s:%d %s"
         (if sock_stream then "SOCK_STREAM" else "SOCK_DGRAM")
         (Ipaddr.V4.to_string local_ip) local_port (Printexc.to_string e))))
      )

let (/) = Filename.concat
let home = try Sys.getenv "HOME" with Not_found -> "/Users/root"
let vsock_path = ref (home / "Library/Containers/com.docker.docker/Data/@connect")
let vsock_port = 62373l

include Hostnet.Conn_lwt_unix

type port = Hostnet.Forward.Port.t

let connect port =
  let open Lwt.Infix in
  Osx_hyperkit.Vsock.connect ~path:!vsock_path ~port:vsock_port ()
  >>= fun fd ->
  (* Matches the Go definition *)
  let proto, ip, port = match port with
    | `Tcp(ip, port) -> 1, ip, port
    | `Udp(ip, port) -> 2, ip, port in
  let header = Cstruct.create (1 + 2 + 4 + 2) in
  Cstruct.set_uint8 header 0 proto;
  Cstruct.LE.set_uint16 header 1 4;
  let ip = Ipaddr.V4.to_bytes ip in
  Cstruct.blit_from_string ip 0 header 3 4;
  Cstruct.LE.set_uint16 header 7 port;
  Lwt_cstruct.(complete (write fd) header)
  >>= fun () ->
  Lwt.return (connect fd)

let (/) = Filename.concat
let home = try Sys.getenv "HOME" with Not_found -> "/Users/root"
let vsock_path = ref (home / "Library/Containers/com.docker.docker/Data/@connect")
let vsock_port = 62373l

include Hostnet.Socket.Stream

let connect () =
  let open Lwt.Infix in
  let description = "vsock port forward" in
  Osx_hyperkit.Vsock.connect ~path:!vsock_path ~port:vsock_port ()
  >>= fun fd ->
  Lwt.return (of_fd ~description fd)

let (/) = Filename.concat
let home = try Sys.getenv "HOME" with Not_found -> "/Users/root"
let vsock_path = ref (home / "Library/Containers/com.docker.docker/Data/@connect")
let vsock_port = 62373l

type proto = TCP | UDP

module Result = struct
  include Result
  let return x = Ok x
  let errorf fmt = Printf.ksprintf (fun s -> Error (`Msg s)) fmt
end

module Port = struct
  type t = {
    proto: proto;
    ip: Ipaddr.V4.t;
    port: int;
  }
  let of_string x =
    try
        match Stringext.split ~on:':' x with
        | [ proto; ip; port ] ->
          let proto = match String.lowercase proto with
          | "tcp" -> TCP
          | "udp" -> UDP
          | x -> raise Not_found in
          let ip = Ipaddr.V4.of_string_exn ip in
          let port = int_of_string port in
          Result.return { proto; ip; port }
        | _ ->
        Result.errorf "port should be of the form proto:IP:port"
    with
      | _ -> Result.Error (`Msg (Printf.sprintf "port is not a proto:IP:port: '%s'" x))
  let to_string { proto; ip; port } =
    let proto = match proto with TCP -> "tcp" | UDP -> "udp" in
    proto ^ ":" ^ (Ipaddr.V4.to_string ip) ^ ":" ^ (string_of_int port)
end

let connect { Port.proto; ip; port } =
  let open Lwt.Infix in
  Osx_hyperkit.Vsock.connect ~path:!vsock_path ~port:vsock_port ()
  >>= fun fd ->
  (* Matches the Go definition *)
  let header = Cstruct.create (1 + 2 + 4 + 2) in
  Cstruct.set_uint8 header 0 (match proto with TCP -> 1 | UDP -> 2);
  Cstruct.LE.set_uint16 header 1 4;
  let ip = Ipaddr.V4.to_bytes ip in
  Cstruct.blit_from_string ip 0 header 3 4;
  Cstruct.LE.set_uint16 header 7 port;
  Lwt_cstruct.(complete (write fd) header)
  >>= fun () ->
  Lwt.return fd

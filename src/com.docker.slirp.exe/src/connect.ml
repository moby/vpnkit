let src =
  let src = Logs.Src.create "usernet" ~doc:"Mirage TCP/IP <-> socket proxy" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let hvsockaddr = ref None

let set_port_forward_addr x = hvsockaddr := Some x

type port = Hostnet.Forward.Port.t

include Flow_lwt_hvsock_shutdown

open Lwt.Infix

let connect port = match !hvsockaddr with
  | None ->
    Log.err (fun f -> f "Please set a Hyper-V socket address for port forwarding");
    failwith "Hyper-V socket forwarding not initialised"
  | Some sockaddr ->
    let fd = Lwt_hvsock.create () in
    Lwt_hvsock.connect fd sockaddr
    >>= fun () ->
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
    let flow = connect fd in
    write flow header
    >>= function
    | `Eof -> Lwt.fail End_of_file
    | `Error e -> Lwt.fail (Failure (error_message e))
    | `Ok () ->
      Lwt.return flow

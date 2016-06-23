let src =
  let src = Logs.Src.create "usernet" ~doc:"Mirage TCP/IP <-> socket proxy" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let hvsockaddr = ref None

let set_port_forward_addr x = hvsockaddr := Some x

include Flow_lwt_hvsock_shutdown

open Lwt.Infix

let connect () = match !hvsockaddr with
  | None ->
    Log.err (fun f -> f "Please set a Hyper-V socket address for port forwarding");
    failwith "Hyper-V socket forwarding not initialised"
  | Some sockaddr ->
    let fd = Lwt_hvsock.create () in
    Lwt_hvsock.connect fd sockaddr
    >>= fun () ->
    Lwt.return (connect fd)

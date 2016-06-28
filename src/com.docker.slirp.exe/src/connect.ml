let src =
  let src = Logs.Src.create "usernet" ~doc:"Mirage TCP/IP <-> socket proxy" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let hvsockaddr = ref None

let set_port_forward_addr x = hvsockaddr := Some x

module Make(Time: V1_LWT.TIME)(Main: Lwt_hvsock.MAIN) = struct
  include Flow_lwt_hvsock_shutdown.Make(Time)(Main)

  open Lwt.Infix

  type address = unit

  let connect () = match !hvsockaddr with
    | None ->
      Log.err (fun f -> f "Please set a Hyper-V socket address for port forwarding");
      failwith "Hyper-V socket forwarding not initialised"
    | Some sockaddr ->
      let fd = Hvsock.create () in
      Hvsock.connect fd sockaddr
      >>= fun () ->
      Lwt.return (connect fd)
end

let src =
  let src = Logs.Src.create "port forward" ~doc:"forward local ports to the VM" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

open Hostnet
open Lwt.Infix

let (/) = Filename.concat
let home = try Sys.getenv "HOME" with Not_found -> "/Users/root"
let vsock_port = 62373l

module Make_unix(Host: Sig.HOST) = struct

  let vsock_path = ref (home / "Library/Containers/com.docker.docker/Data/@connect")

  include Host.Sockets.Stream.Unix

  let connect () =
    connect (!vsock_path)
    >>= function
    | `Error (`Msg msg) ->
      Log.err (fun f -> f "vsock connect write got %s" msg);
      Lwt.fail (Failure msg)
    | `Ok flow ->
      let address = Cstruct.of_string (Printf.sprintf "00000003.%08lx\n" vsock_port) in
      write flow address
      >>= function
      | `Eof ->
        Log.err (fun f -> f "vsock connect write got Eof");
        close flow
        >>= fun () ->
        Lwt.fail End_of_file
      | `Error e ->
        let msg = error_message e in
        Log.err (fun f -> f "vsock connect write got %s" msg);
        close flow
        >>= fun () ->
        Lwt.fail (Failure msg)
      | `Ok () ->
        Lwt.return flow
end

module Make_hvsock(Host: Sig.HOST) = struct
  module F = Flow_lwt_hvsock_shutdown.Make(Host.Time)(Host.Main)

  type flow = {
    idx: int;
    flow: F.flow;
  }

  type address = unit

  let hvsockaddr = ref None

  let set_port_forward_addr x = hvsockaddr := Some x

  let close flow =
    Host.Sockets.deregister_connection flow.idx;
    F.close flow.flow

  let connect () = match !hvsockaddr with
    | None ->
      Log.err (fun f -> f "Please set a Hyper-V socket address for port forwarding");
      failwith "Hyper-V socket forwarding not initialised"
    | Some sockaddr ->
      let description = "hvsock" in
      Host.Sockets.register_connection description
      >>= fun idx ->
      let fd = F.Hvsock.create () in
      F.Hvsock.connect fd sockaddr
      >>= fun () ->
      let flow = F.connect fd in
      Lwt.return { idx; flow }

  let read_into t = F.read_into t.flow
  let read t = F.read t.flow
  let write t = F.write t.flow 
  let writev t = F.writev t.flow
  let shutdown_read t = F.shutdown_read t.flow
  let shutdown_write t = F.shutdown_write t.flow
  let error_message = F.error_message
  type 'a io = 'a F.io
  type buffer = F.buffer
  type error = F.error
end

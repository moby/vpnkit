let src =
  let src = Logs.Src.create "port forward" ~doc:"forward local ports to the VM" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

open Hostnet

let (/) = Filename.concat
let home = try Sys.getenv "HOME" with Not_found -> "/Users/root"
let vsock_port = 62373l

module Make(Socket: Sig.SOCKETS) = struct

  let vsock_path = ref (home / "Library/Containers/com.docker.docker/Data/@connect")

  include Socket.Stream.Unix

  let connect () =
    let open Lwt.Infix in
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
        Lwt.fail End_of_file
      | `Error e ->
        let msg = error_message e in
        Log.err (fun f -> f "vsock connect write got %s" msg);
        Lwt.fail (Failure msg)
      | `Ok () ->
        Lwt.return flow
end

let src =
  let src = Logs.Src.create "port forward" ~doc:"forward local ports to the VM" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

open Hostnet

let (/) = Filename.concat
let home = try Sys.getenv "HOME" with Not_found -> "/Users/root"
let vsock_port = 62373l

module Make(Host: Sig.HOST) = struct

  let vsock_path = ref (home / "Library/Containers/com.docker.docker/Data/@connect")

  let max_connections = ref None

  let set_max_connections x = max_connections := x

  include Host.Sockets.Stream.Unix

  let active_connections = ref 0

  let close flow =
    decr active_connections;
    close flow

  let connect () =
    let open Lwt.Infix in
    ( match !max_connections with
      | Some m when !active_connections >= m ->
        Log.err (fun f -> f "exceeded maximum number of forwarded connections (%d)" m);
        Lwt.fail End_of_file
      | _ ->
        incr active_connections;
        Lwt.return_unit )
    >>= fun () ->
    connect (!vsock_path)
    >>= function
    | `Error (`Msg msg) ->
      decr active_connections;
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

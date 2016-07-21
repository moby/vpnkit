let src =
  let src = Logs.Src.create "usernet" ~doc:"Mirage TCP/IP <-> socket proxy" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

open Hostnet

module Make(Host: Sig.HOST) = struct
  include Flow_lwt_hvsock_shutdown.Make(Host.Time)(Host.Main)

  open Lwt.Infix

  type address = unit

  let hvsockaddr = ref None

  let set_port_forward_addr x = hvsockaddr := Some x

  let max_connections = ref None

  let set_max_connections x = max_connections := x

  let active_connections = ref 0

  let close flow =
    decr active_connections;
    close flow

  let connect () = match !hvsockaddr with
    | None ->
      Log.err (fun f -> f "Please set a Hyper-V socket address for port forwarding");
      failwith "Hyper-V socket forwarding not initialised"
    | Some sockaddr ->
      ( match !max_connections with
        | Some m when !active_connections >= m ->
          Log.err (fun f -> f "exceeded maximum number of forwarded connections (%d)" m);
          Lwt.fail End_of_file
        | _ ->
          incr active_connections;
          Lwt.return_unit )
      >>= fun () ->
      let fd = Hvsock.create () in
      Hvsock.connect fd sockaddr
      >>= fun () ->
      Lwt.return (connect fd)
end

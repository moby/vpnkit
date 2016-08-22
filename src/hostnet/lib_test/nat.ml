open Hostnet
open Lwt.Infix

let src =
  let src = Logs.Src.create "test" ~doc:"Test the slirp stack" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Make(Host: Sig.HOST) = struct

module Slirp_stack = Slirp_stack.Make(Host)
open Slirp_stack

module EchoServer = struct
  (* Receive UDP packets and copy them back to sender *)
  type t = {
    local_port: int;
    server: Host.Sockets.Datagram.Udp.server;
  }

  let create () =
    Host.Sockets.Datagram.Udp.bind (Ipaddr.(V4 V4.localhost), 0)
    >>= fun server ->
    let _, local_port = Host.Sockets.Datagram.Udp.getsockname server in
    (* Start a background echo thread. This will naturally fail when the
       file descriptor is closed underneath it from `shutdown` *)
    let _ =
      let buf = Cstruct.create 2048 in
      let rec loop () =
        Host.Sockets.Datagram.Udp.recvfrom server buf
        >>= fun (len, address) ->
        Host.Sockets.Datagram.Udp.sendto server address (Cstruct.sub buf 0 len)
        >>= fun () ->
        loop () in
      loop () in
    Lwt.return { local_port; server }

  let to_string t =
    Printf.sprintf "udp:127.0.0.1:%d" t.local_port
  let destroy t = Host.Sockets.Datagram.Udp.shutdown t.server
  let with_server f =
    create ()
    >>= fun server ->
    Lwt.finalize
      (fun () ->
        f server
      ) (fun () ->
        destroy server
      )
end

(* Start a local UDP echo server, send traffic to it and listen for a response *)
let test_udp () =
  let t =
    EchoServer.with_server
      (fun { EchoServer.local_port } ->
        with_stack
          (fun stack ->
            let virtual_port = 1024 in
            let t, u = Lwt.task () in
            Client.listen_udpv4 stack ~port:virtual_port
              (fun ~src ~dst ~src_port buffer ->
                Lwt.wakeup u ();
                Lwt.return_unit;
              );
            let buffer = Cstruct.create 1024 in
            Cstruct.memset buffer 0;
            let rec loop remaining =
              if remaining = 0 then failwith "Timed-out before UDP response arrived";
              let udpv4 = Client.udpv4 stack in
              Client.UDPV4.write ~source_port:virtual_port ~dest_ip:Ipaddr.V4.localhost ~dest_port:local_port udpv4 buffer
              >>= fun () ->
              Lwt.pick [ t; Host.Time.sleep 1. ]
              >>= fun () ->
              if Lwt.state t = Lwt.Sleep then loop (remaining - 1) else Lwt.return_unit in
            loop 5
          )
        ) in
  Host.Main.run t

let suite = [
  "1 UDP connection", `Quick, test_udp;
]
end

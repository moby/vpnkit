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
  (* Receive UDP packets and copy them back to all senders. Roughly simulates
     a chat protocol, in particular this allows us to test many replies to one
     request. *)
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
      let seen_addresses = ref [] in
      let rec loop () =
        Host.Sockets.Datagram.Udp.recvfrom server buf
        >>= fun (len, address) ->
        seen_addresses := address :: !seen_addresses;
        Lwt_list.iter_p
          (fun address ->
            Host.Sockets.Datagram.Udp.sendto server address (Cstruct.sub buf 0 len)
          ) !seen_addresses
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

module UdpServer = struct
  type t = {
    port: int;
    mutable highest: int; (* highest packet payload received *)
    c: unit Lwt_condition.t;
  }
  let make stack port =
    let highest = 0 in
    let c = Lwt_condition.create () in
    let t = { port; highest; c } in
    Client.listen_udpv4 stack ~port
      (fun ~src ~dst ~src_port buffer ->
        t.highest <- max t.highest (Cstruct.get_uint8 buffer 0);
        Log.debug (fun f -> f "Received UDP %d -> %d highest %d" src_port port t.highest);
        Lwt_condition.signal c ();
        Lwt.return_unit
      );
    t
  let rec wait_for ~timeout ~highest t =
    if t.highest < highest then begin
      Lwt.pick [ Lwt_condition.wait t.c; Host.Time.sleep 1. ]
      >>= fun () ->
      Lwt.return (t.highest >= highest)
    end else Lwt.return true
end

(* Start a local UDP mult-echo server, send traffic to it from one source port,
   wait for the response, send traffic to it from another source port, expect
   responses to *both* source ports. *)
let test_udp_2 () =
  let t =
    EchoServer.with_server
      (fun { EchoServer.local_port } ->
        with_stack
          (fun stack ->
            let buffer = Cstruct.create 1024 in
            (* Send '1' *)
            Cstruct.set_uint8 buffer 0 1;
            let udpv4 = Client.udpv4 stack in

            (* Listen on one virtual source port and count received packets *)
            let virtual_port1 = 1024 in
            let server1 = UdpServer.make stack virtual_port1 in

            let rec loop remaining =
              if remaining = 0 then failwith "Timed-out before UDP response arrived";
              Log.debug (fun f -> f "Sending %d -> %d value %d" virtual_port1 local_port (Cstruct.get_uint8 buffer 0));
              Client.UDPV4.write ~source_port:virtual_port1 ~dest_ip:Ipaddr.V4.localhost ~dest_port:local_port udpv4 buffer
              >>= fun () ->
              UdpServer.wait_for ~timeout:1. ~highest:1 server1
              >>= function
              | true -> Lwt.return_unit
              | false -> loop (remaining - 1) in
            loop 5
            >>= fun () ->
            (* Listen on a second virtual source port and count received packets *)
            (* Send '2' *)
            Cstruct.set_uint8 buffer 0 2;
            let virtual_port2 = 1025 in
            let server2 = UdpServer.make stack virtual_port2 in
            let rec loop remaining =
              if remaining = 0 then failwith "Timed-out before UDP response arrived";
              Log.debug (fun f -> f "Sending %d -> %d value %d" virtual_port2 local_port (Cstruct.get_uint8 buffer 0));
              Client.UDPV4.write ~source_port:virtual_port2 ~dest_ip:Ipaddr.V4.localhost ~dest_port:local_port udpv4 buffer
              >>= fun () ->
              UdpServer.wait_for ~timeout:1. ~highest:2 server2
              >>= fun ok2 ->
              (* The server should "multicast" the packet to the original "connection" *)
              UdpServer.wait_for ~timeout:1. ~highest:2 server1
              >>= fun ok1 ->
              if ok1 && ok2 then Lwt.return_unit else loop (remaining - 1) in
            loop 5
          )
        ) in
  Host.Main.run t

let suite = [
  "1 UDP connection", `Quick, test_udp;
  "2 UDP connections", `Quick, test_udp_2;
]
end

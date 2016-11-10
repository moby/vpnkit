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
      mutable seen_addresses: Host.Sockets.Datagram.address list;
    }

    let create () =
      Host.Sockets.Datagram.Udp.bind (Ipaddr.(V4 V4.localhost), 0)
      >>= fun server ->
      let _, local_port = Host.Sockets.Datagram.Udp.getsockname server in
      (* Start a background echo thread. This will naturally fail when the
         file descriptor is closed underneath it from `shutdown` *)
      let seen_addresses = [] in
      let t = { local_port; server; seen_addresses } in
      let _ =
        let buf = Cstruct.create 2048 in
        let rec loop () =
          Host.Sockets.Datagram.Udp.recvfrom server buf
          >>= fun (len, address) ->
          t.seen_addresses <- address :: t.seen_addresses;
          Lwt_list.iter_p
            (fun address ->
               Host.Sockets.Datagram.Udp.sendto server address (Cstruct.sub buf 0 len)
            ) t.seen_addresses
          >>= fun () ->
          loop () in
        loop () in
      Lwt.return t

    let get_seen_addresses t = t.seen_addresses

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

  module UdpServer = struct
    module PortSet = Set.Make(struct type t = int let compare = Pervasives.compare end)

    type t = {
      port: int;
      mutable highest: int; (* highest packet payload received *)
      mutable seen_source_ports: PortSet.t; (* all source addresses seen *)
      c: unit Lwt_condition.t;
    }
    let make stack port =
      let highest = 0 in
      let c = Lwt_condition.create () in
      let seen_source_ports = PortSet.empty in
      let t = { port; highest; seen_source_ports; c } in
      Client.listen_udpv4 stack ~port
        (fun ~src ~dst ~src_port buffer ->
           t.highest <- max t.highest (Cstruct.get_uint8 buffer 0);
           t.seen_source_ports <- PortSet.add src_port t.seen_source_ports;
           Log.debug (fun f -> f "Received UDP %d -> %d highest %d" src_port port t.highest);
           Lwt_condition.signal c ();
           Lwt.return_unit
        );
      t
    let rec wait_for_data ~timeout ~highest t =
      if t.highest < highest then begin
        Lwt.pick [ Lwt_condition.wait t.c; Host.Time.sleep 1. ]
        >>= fun () ->
        Lwt.return (t.highest >= highest)
      end else Lwt.return true
    let rec wait_for_ports ~timeout ~num t =
      if PortSet.cardinal t.seen_source_ports < num then begin
        Lwt.pick [ Lwt_condition.wait t.c; Host.Time.sleep 1. ]
        >>= fun () ->
        Lwt.return (PortSet.cardinal t.seen_source_ports >= num)
      end else Lwt.return true
  end

  (* Start a local UDP echo server, send traffic to it and listen for a response *)
  let test_udp () =
    let t =
      EchoServer.with_server
        (fun { EchoServer.local_port } ->
           with_stack
             (fun stack ->
                let buffer = Cstruct.create 1024 in
                (* Send '1' *)
                Cstruct.set_uint8 buffer 0 1;
                let udpv4 = Client.udpv4 stack in
                let virtual_port = 1024 in
                let server = UdpServer.make stack virtual_port in

                let rec loop remaining =
                  if remaining = 0 then failwith "Timed-out before UDP response arrived";
                  Log.debug (fun f -> f "Sending %d -> %d value %d" virtual_port local_port (Cstruct.get_uint8 buffer 0));
                  Client.UDPV4.write ~source_port:virtual_port ~dest_ip:Ipaddr.V4.localhost ~dest_port:local_port udpv4 buffer
                  >>= fun () ->
                  UdpServer.wait_for_data ~timeout:1. ~highest:1 server
                  >>= function
                  | true -> Lwt.return_unit
                  | false -> loop (remaining - 1) in
                loop 5
             )
        ) in
    Host.Main.run t

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
                  UdpServer.wait_for_data ~timeout:1. ~highest:1 server1
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
                  UdpServer.wait_for_data ~timeout:1. ~highest:2 server2
                  >>= fun ok2 ->
                  (* The server should "multicast" the packet to the original "connection" *)
                  UdpServer.wait_for_data ~timeout:1. ~highest:2 server1
                  >>= fun ok1 ->
                  if ok1 && ok2 then Lwt.return_unit else loop (remaining - 1) in
                loop 5
             )
        ) in
    Host.Main.run t

  (* Start a local UDP echo server, send some traffic to it over the virtual interface.
     Send traffic to the outside address on a second physical interface, check that
     this external third party can traverse the NAT *)
  let test_nat_punch () =
    let t =
      EchoServer.with_server
        (fun echoserver ->
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
                  let dest_port = echoserver.EchoServer.local_port in
                  Log.debug (fun f -> f "Sending %d -> %d value %d" virtual_port1 dest_port (Cstruct.get_uint8 buffer 0));
                  Client.UDPV4.write ~source_port:virtual_port1 ~dest_ip:Ipaddr.V4.localhost ~dest_port udpv4 buffer
                  >>= fun () ->
                  UdpServer.wait_for_data ~timeout:1. ~highest:1 server1
                  >>= function
                  | true -> Lwt.return_unit
                  | false -> loop (remaining - 1) in
                loop 5
                >>= fun () ->

                (* Using the physical outside interface, send traffic to the address
                   and see if this traffic will also be sent via the NAT. *)
                (* Send '2' *)
                Cstruct.set_uint8 buffer 0 2;
                Host.Sockets.Datagram.Udp.bind (Ipaddr.(V4 V4.localhost), 0)
                >>= fun client ->
                let _, source_port = Host.Sockets.Datagram.Udp.getsockname client in
                let address = List.hd (EchoServer.get_seen_addresses echoserver) in
                let _, dest_port = address in
                let rec loop remaining =
                  if remaining = 0 then failwith "Timed-out before UDP response arrived";
                  Log.debug (fun f -> f "Sending %d -> %d value %d" source_port dest_port (Cstruct.get_uint8 buffer 0));
                  Host.Sockets.Datagram.Udp.sendto client address buffer
                  >>= fun () ->
                  UdpServer.wait_for_data ~timeout:1. ~highest:2 server1
                  >>= function
                  | true -> Lwt.return_unit
                  | false -> loop (remaining - 1) in
                loop 5
             )
        ) in
    Host.Main.run t

  (* The NAT table rule should be associated with the virtual address, rather
     than physical address. Check if we have 2 physical servers we have only a
     single NAT rule *)
  let test_shared_nat_rule () =
    let t =
      EchoServer.with_server
        (fun { EchoServer.local_port } ->
           with_stack
             (fun stack ->
                let buffer = Cstruct.create 1024 in
                (* Send '1' *)
                Cstruct.set_uint8 buffer 0 1;
                let udpv4 = Client.udpv4 stack in
                let virtual_port = 1024 in
                let server = UdpServer.make stack virtual_port in
                let init_table_size = Host.Sockets.Datagram.get_nat_table_size () in

                let rec loop remaining =
                  if remaining = 0 then failwith "Timed-out before UDP response arrived";
                  Log.debug (fun f -> f "Sending %d -> %d value %d" virtual_port local_port (Cstruct.get_uint8 buffer 0));
                  Client.UDPV4.write ~source_port:virtual_port ~dest_ip:Ipaddr.V4.localhost ~dest_port:local_port udpv4 buffer
                  >>= fun () ->
                  UdpServer.wait_for_data ~timeout:1. ~highest:1 server
                  >>= function
                  | true -> Lwt.return_unit
                  | false -> loop (remaining - 1) in
                loop 5
                >>= fun () ->
                Alcotest.(check int) "One NAT rule" 1 (Host.Sockets.Datagram.get_nat_table_size () - init_table_size);
                (* Send '2' *)
                Cstruct.set_uint8 buffer 0 2;
                (* Create another physical server and send traffic from the same
                   virtual address *)
                EchoServer.with_server
                  (fun { EchoServer.local_port } ->
                     let rec loop remaining =
                       if remaining = 0 then failwith "Timed-out before UDP response arrived";
                       Log.debug (fun f -> f "Sending %d -> %d value %d" virtual_port local_port (Cstruct.get_uint8 buffer 0));
                       Client.UDPV4.write ~source_port:virtual_port ~dest_ip:Ipaddr.V4.localhost ~dest_port:local_port udpv4 buffer
                       >>= fun () ->
                       UdpServer.wait_for_data ~timeout:1. ~highest:2 server
                       >>= function
                       | true -> Lwt.return_unit
                       | false -> loop (remaining - 1) in
                     loop 5
                     >>= fun () ->
                     Alcotest.(check int) "Still one NAT rule" 1 (Host.Sockets.Datagram.get_nat_table_size () - init_table_size);
                     Lwt.return_unit
                  )
             )
        ) in
    Host.Main.run t

  (* If we have two physical servers but send data from the same source port,
     we should see both physical server source ports *)
  let test_source_ports () =
    let t =
      EchoServer.with_server
        (fun { EchoServer.local_port = local_port1 } ->
          EchoServer.with_server
            (fun { EchoServer.local_port = local_port2 } ->
               with_stack
                 (fun stack ->
                    let buffer = Cstruct.create 1024 in
                    let udpv4 = Client.udpv4 stack in
                    (* This is the port we shall send from *)
                    let virtual_port = 1024 in
                    let server = UdpServer.make stack virtual_port in
                    let rec loop remaining =
                    Printf.fprintf stderr "remaining=%d\n%!" remaining;
                      if remaining = 0 then failwith "Timed-out before both UDP ports were seen";
                      Log.debug (fun f -> f "Sending %d -> %d value %d" virtual_port local_port1 (Cstruct.get_uint8 buffer 0));
                      Client.UDPV4.write ~source_port:virtual_port ~dest_ip:Ipaddr.V4.localhost ~dest_port:local_port1 udpv4 buffer
                      >>= fun () ->
                      Log.debug (fun f -> f "Sending %d -> %d value %d" virtual_port local_port2 (Cstruct.get_uint8 buffer 0));
                      Client.UDPV4.write ~source_port:virtual_port ~dest_ip:Ipaddr.V4.localhost ~dest_port:local_port2 udpv4 buffer
                      >>= fun () ->
                      UdpServer.wait_for_ports ~timeout:1. ~num:2 server
                      >>= function
                      | true -> Lwt.return_unit
                      | false -> loop (remaining - 1) in
                    loop 5
                  )
            )
        ) in
    Host.Main.run t

  let suite = [
    "Shared NAT rule", `Quick, test_shared_nat_rule;
    "1 UDP connection", `Quick, test_udp;
    "2 UDP connections", `Quick, test_udp_2;
    "NAT punch", `Quick, test_nat_punch;
    "Source ports", `Quick, test_source_ports;
  ]
end

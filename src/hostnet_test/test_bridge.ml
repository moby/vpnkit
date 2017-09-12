open Lwt.Infix
open Slirp_stack

let src =
  let src = Logs.Src.create "vnet" ~doc:"Test the virtual network" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

exception Test_failure of string

(* Open multiple connections and verify that the connection succeeds and MAC and IP changes *)
let test_connect n () =
    Host.Main.run begin
        let rec loop x used_ips used_macs =
            match x, used_ips, used_macs with 
            | 0, _, _ -> Lwt.return_unit
            | x, used_ips, used_macs -> 
                let uuid = (Uuidm.v `V4) in
                with_stack ~uuid ~pcap:"test_connect.pcap" (fun _ client_stack ->
                    (* Same IP should not appear twice *)
                    let ips = Client.IPV4.get_ip (Client.ipv4 client_stack.t) in
                    assert(List.length ips == 1);
                    let ip = List.hd ips in
                    assert((List.mem ip used_ips) == false);

                    (* Same MAC should not appear twice *)
                    let mac = (VMNET.mac client_stack.netif) in
                    assert((List.mem mac used_macs) == false);

                    Lwt.return (ip, mac)
                ) >>= fun (ip, mac) -> 
                Log.info (fun f -> f "Stack %d got IP %s and MAC %s" x (Ipaddr.V4.to_string ip) (Macaddr.to_string mac));
                loop (x - 1) ([ip] @ used_ips) ([mac] @ used_macs)
        in
        loop n [] []
    end

(* Connect twice with the same UUID and verify that MAC and IP are the same *)
let test_reconnect () =
    Host.Main.run begin
        let uuid = (Uuidm.v `V4) in
        Log.info (fun f -> f "Using UUID %s" (Uuidm.to_string uuid));
        with_stack ~uuid ~pcap:"test_reconnect.pcap" (fun _ client_stack ->
            let ips = Client.IPV4.get_ip (Client.ipv4 client_stack.t) in
            let ip = List.hd ips in
            let mac = (VMNET.mac client_stack.netif) in
            Lwt.return (ip, mac)
        ) >>= fun (ip, mac) -> 
        Log.info (fun f -> f "First connection got IP %s and MAC %s" (Ipaddr.V4.to_string ip) (Macaddr.to_string mac));
        with_stack ~uuid ~pcap:"test_reconnect.2.pcap" (fun _ client_stack ->
            let ips = Client.IPV4.get_ip (Client.ipv4 client_stack.t) in
            let ip = List.hd ips in
            let mac = (VMNET.mac client_stack.netif) in
            Lwt.return (ip, mac)
        ) >>= fun (reconnect_ip, reconnect_mac) -> 
        Log.info (fun f -> f "Reconnect got IP %s and MAC %s" (Ipaddr.V4.to_string reconnect_ip) (Macaddr.to_string reconnect_mac));
        assert(Ipaddr.V4.compare ip reconnect_ip == 0);
        assert(Macaddr.compare mac reconnect_mac == 0);
        Lwt.return ()
   end

(* Connect with random UUID and request an unused IP *)
let test_connect_preferred_ipv4 preferred_ip () =
    Host.Main.run begin
        let uuid = (Uuidm.v `V4) in
        Log.info (fun f -> f "Using UUID %s, requesting IP %s" (Uuidm.to_string uuid) (Ipaddr.V4.to_string preferred_ip));
        with_stack ~uuid ~preferred_ip ~pcap:"test_connect_preferred_ipv4.pcap" (fun _ client_stack ->
            let ips = Client.IPV4.get_ip (Client.ipv4 client_stack.t) in
            let ip = List.hd ips in
            let mac = (VMNET.mac client_stack.netif) in
            Lwt.return (ip, mac)
        ) >>= fun (ip, mac) -> 
        (* Verify that we got the IP we requested *)
        assert(Ipaddr.V4.compare ip preferred_ip == 0);
        Log.info (fun f -> f "First connection got IP %s and MAC %s" (Ipaddr.V4.to_string ip) (Macaddr.to_string mac));
        with_stack ~uuid ~preferred_ip ~pcap:"test_connect_preferred_ipv4.2.pcap" (fun _ client_stack ->
            let ips = Client.IPV4.get_ip (Client.ipv4 client_stack.t) in
            let ip = List.hd ips in
            let mac = (VMNET.mac client_stack.netif) in
            Lwt.return (ip, mac)
        ) >>= fun (reconnect_ip, reconnect_mac) -> 
        Log.info (fun f -> f "Reconnect got IP %s and MAC %s" (Ipaddr.V4.to_string reconnect_ip) (Macaddr.to_string reconnect_mac));
        (* Verify that we got the same IP and MAC when reconnecting with the same UUID *)
        assert(Ipaddr.V4.compare ip reconnect_ip == 0);
        assert(Macaddr.compare mac reconnect_mac == 0);
        (* Try to reconnect with the same UUID, but request a different IP (this should fail) *)
        let different_ip = Ipaddr.V4.of_int32 (Int32.succ (Ipaddr.V4.to_int32 preferred_ip)) in
        Lwt.catch (fun () ->
            with_stack ~uuid ~preferred_ip:different_ip ~pcap:"test_connect_preferred_ipv4.3.pcap" (fun _ client_stack ->
                let ips = Client.IPV4.get_ip (Client.ipv4 client_stack.t) in
                let ip = List.hd ips in
                let mac = (VMNET.mac client_stack.netif) in
                Lwt.return (ip, mac)
            ) >>= fun (reconnect_ip, reconnect_mac) -> 
            Log.err (fun f -> f "Failure: Request for different IP got IP %s and MAC %s" (Ipaddr.V4.to_string reconnect_ip) (Macaddr.to_string reconnect_mac));
            raise (Test_failure "Request for different IP for same UUID succeeded"))
            (fun e -> match e with
             | Failure _ -> Lwt.return () (* test was successful, an exception was triggered *)
             | e -> raise e) >>= fun () ->
        (* Try to reconnect with a different UUID, but request a used IP (this should fail) *)
        Lwt.catch (fun () ->
            let uuid = (Uuidm.v `V4) in
            with_stack ~uuid ~preferred_ip ~pcap:"test_connect_preferred_ipv4.4.pcap" (fun _ client_stack ->
                let ips = Client.IPV4.get_ip (Client.ipv4 client_stack.t) in
                let ip = List.hd ips in
                let mac = (VMNET.mac client_stack.netif) in
                Lwt.return (ip, mac)
            ) >>= fun (reconnect_ip, reconnect_mac) -> 
            Log.err (fun f -> f "Failure: Request for same IP with different UUID got IP %s and MAC %s" (Ipaddr.V4.to_string reconnect_ip) (Macaddr.to_string reconnect_mac));
            raise (Test_failure "Request for same IP with different UUID succeeded"))
            (fun e -> match e with
             | Failure _ -> Lwt.return () (* test was successful, an exception was triggered *)
             | e -> raise e) >>= fun () ->
        Lwt.return ()
   end


let tests = 
    [ "Vnet bridge", 
      [ ("connect 2 nodes", `Quick, (test_connect 2)) ;
        ("connect 10 nodes", `Quick, (test_connect 10)) ;
        ("reconnect node", `Quick, test_reconnect) ;
        ("preferred_ipv4", `Quick, (test_connect_preferred_ipv4 preferred_ip1));
      ]
    ]



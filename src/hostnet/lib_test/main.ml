open Hostnet
open Lwt.Infix

let src =
  let src = Logs.Src.create "test" ~doc:"Test the slirp stack" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Resolv_conf = struct
  let get () = Lwt.return [
    Ipaddr.V4 (Ipaddr.V4.of_string_exn "8.8.8.8"), 53;
    Ipaddr.V4 (Ipaddr.V4.of_string_exn "8.8.4.4"), 53;
  ]
  let set _ = ()
  let set_default_dns _ = ()
end

module Make(Host: Sig.HOST) = struct
module VMNET = Vmnet.Make(Host.Sockets.Stream.Tcp)
module Config = Active_config.Make(Host.Time)(Host.Sockets.Stream.Unix)
module Slirp_stack = Slirp.Make(Config)(VMNET)(Resolv_conf)(Host)

module Client = struct
  module Netif = VMNET
  module Ethif1 = Ethif.Make(Netif)
  module Arpv41 = Arpv4.Make(Ethif1)(Clock)(Host.Time)
  module Ipv41 = Ipv4.Make(Ethif1)(Arpv41)
  module Udp1 = Udp.Make(Ipv41)
  module Tcp1 = Tcp.Flow.Make(Ipv41)(Host.Time)(Clock)(Random)
  include Tcpip_stack_direct.Make(Console_unix)(Host.Time)
      (Random)(Netif)(Ethif1)(Arpv41)(Ipv41)(Udp1)(Tcp1)
  let or_error name m =
    let open Lwt.Infix in
    m >>= function
    | `Error _ -> failwith (Printf.sprintf "Failed to connect %s device" name)
    | `Ok x -> Lwt.return x
  let connect (interface: VMNET.t) =
    let open Lwt.Infix in
    or_error "console" @@ Console_unix.connect "0"
    >>= fun console ->
    or_error "ethernet" @@ Ethif1.connect interface
    >>= fun ethif ->
    or_error "arp" @@ Arpv41.connect ethif
    >>= fun arp ->
    or_error "ipv4" @@ Ipv41.connect ethif arp
    >>= fun ipv4 ->
    or_error "udp" @@ Udp1.connect ipv4
    >>= fun udp4 ->
    or_error "tcp" @@ Tcp1.connect ipv4
    >>= fun tcp4 ->
    let cfg = {
      V1_LWT. name = "stackv4_ip";
      console;
      interface;
      mode = `DHCP;
    } in
    or_error "stack" @@ connect cfg ethif arp ipv4 udp4 tcp4
    >>= fun stack ->
    Lwt.return stack
end

module DNS = Dns_resolver_mirage.Make(Host.Time)(Client)

let primary_dns_ip = Ipaddr.V4.of_string_exn "192.168.65.1"

let extra_dns_ip = List.map Ipaddr.V4.of_string_exn [
"192.168.65.3"; "192.168.65.4"; "192.168.65.5"; "192.168.65.6";
"192.168.65.7"; "192.168.65.8"; "192.168.65.9"; "192.168.65.10";
]

let config =
  let never, _ = Lwt.task () in
  {
    Slirp.peer_ip = Ipaddr.V4.of_string_exn "192.168.65.2";
    local_ip = Ipaddr.V4.of_string_exn "192.168.65.1";
    extra_dns_ip;
    pcap_settings = Active_config.Value(None, never);
  }

let start_stack () =
  Host.Sockets.Stream.Tcp.bind (Ipaddr.V4.localhost, 0)
  >>= fun server ->
  let _, port = Host.Sockets.Stream.Tcp.getsockname server in
  Host.Sockets.Stream.Tcp.listen server
    (fun flow ->
      Slirp_stack.connect config flow
      >>= fun stack ->
      Log.info (fun f -> f "stack connected");
      Slirp_stack.after_disconnect stack
      >>= fun () ->
      Log.info (fun f -> f "stack disconnected");
      Lwt.return ()
    );
  Lwt.return port

let stack_port = start_stack ()

let with_stack f =
  stack_port
  >>= fun port ->
  Host.Sockets.Stream.Tcp.connect (Ipaddr.V4.localhost, port)
  >>= function
  | `Error (`Msg x) -> failwith x
  | `Ok flow ->
  Log.info (fun f -> f "Made a loopback connection");
  let client_macaddr = Hostnet.Slirp.client_macaddr in
  let server_macaddr = Hostnet.Slirp.server_macaddr in
  VMNET.client_of_fd ~client_macaddr:server_macaddr ~server_macaddr:client_macaddr flow
  >>= function
  | `Error (`Msg x ) ->
    (* Server will close when it gets EOF *)
    Host.Sockets.Stream.Tcp.close flow
    >>= fun () ->
    failwith x
  | `Ok client' ->
    Lwt.finalize (fun () ->
      Log.info (fun f -> f "Initialising client TCP/IP stack");
      Client.connect client'
      >>= fun stack ->
      f stack
    ) (fun () ->
      (* Server will close when it gets EOF *)
      VMNET.disconnect client'
    )

let test_dhcp_query () =
  let t =
    with_stack
      (fun stack ->
        let ips = List.map Ipaddr.V4.to_string (Client.IPV4.get_ip (Client.ipv4 stack)) in
        Log.info (fun f -> f "Got an IP: %s" (String.concat ", " ips));
        Lwt.return ()
      ) in
  Host.Main.run t

let test_dns_query server () =
  let t =
    with_stack
      (fun stack ->
        let resolver = DNS.create stack in
        DNS.gethostbyname ~server resolver "www.google.com"
        >>= fun ips ->
        Log.info (fun f -> f "www.google.com has IPs: %s" (String.concat ", " (List.map Ipaddr.to_string ips)));
        Lwt.return ()
      ) in
  Host.Main.run t

let test_http_fetch () =
  let t =
    with_stack
      (fun stack ->
        let resolver = DNS.create stack in
        DNS.gethostbyname resolver "www.google.com"
        >>= function
        | Ipaddr.V4 ip :: _ ->
          begin Client.TCPV4.create_connection (Client.tcpv4 stack) (ip, 80)
          >>= function
          | `Ok flow ->
            Log.info (fun f -> f "Connected to www.google.com:80");
            let page = Io_page.(to_cstruct (get 1)) in
            let http_get = "GET / HTTP/1.0\nHost: anil.recoil.org\n\n" in
            Cstruct.blit_from_string http_get 0 page 0 (String.length http_get);
            let buf = Cstruct.sub page 0 (String.length http_get) in
            begin Client.TCPV4.write flow buf >>= function
            | `Eof     ->
              Log.err (fun f -> f "EOF writing HTTP request to www.google.com:80");
              failwith "EOF on writing HTTP GET"
            | `Error _ ->
              Log.err (fun f -> f "Failure writing HTTP request to www.google.com:80");
              failwith "Failure on writing HTTP GET"
            | `Ok _buf ->
              let rec loop total_bytes =
                Client.TCPV4.read flow >>= function
                | `Eof ->
                  Lwt.return total_bytes
                | `Error _ ->
                  Log.err (fun f -> f "Failure read HTTP response from www.google.com:80");
                  failwith "Failure on reading HTTP GET"
                | `Ok buf ->
                  Log.info (fun f -> f "Read %d bytes from www.google.com:80" (Cstruct.len buf));
                  Log.info (fun f -> f "%s" (Cstruct.to_string buf));
                  loop (total_bytes + (Cstruct.len buf)) in
              loop 0
              >>= fun total_bytes ->
              Log.info (fun f -> f "Response had %d total bytes" total_bytes);
              if total_bytes == 0 then failwith "response was empty";
              Lwt.return ()
            end
          | `Error _ ->
            Log.err (fun f -> f "Failed to connect to www.google.com:80");
            failwith "http_fetch"
          end
        | _ ->
          Log.err (fun f -> f "Failed to look up an IPv4 address for www.google.com");
          failwith "http_fetch dns"
      ) in
  Host.Main.run t

let test_dhcp = [
  "Simple query", `Quick, test_dhcp_query;
]

let test_dns = [
  "Use 8.8.8.8 to lookup www.google.com", `Quick, test_dns_query primary_dns_ip;
] @ (List.map (fun ip ->
  "Use 8.8.8.8 to lookup www.google.com via " ^ (Ipaddr.V4.to_string ip), `Quick, test_dns_query ip;
  ) extra_dns_ip
)

let test_tcp = [
  "HTTP GET http://www.google.com/", `Quick, test_http_fetch;
]

module F = Forwarding.Make(Host)

let suite = [
  "DHCP", test_dhcp;
  "DNS UDP", test_dns;
  "TCP", test_tcp;
  "Forwarding", F.test;
]
end

module Slirp_lwt_unix = Make(Host_lwt_unix)
module Slirp_uwt = Make(Host_uwt)

let tests =
  (List.map (fun (name, test) -> name ^ " with Lwt_unix", test) Slirp_lwt_unix.suite) @
  (List.map (fun (name, test) -> name ^ " with Uwt", test) Slirp_uwt.suite) @
  Resolver_test.suite

(* Run it *)
let () =
  Logs.set_reporter (Logs_fmt.reporter ());
  Alcotest.run "Hostnet" tests

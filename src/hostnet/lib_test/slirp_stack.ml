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
end

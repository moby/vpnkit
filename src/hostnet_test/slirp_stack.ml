open Lwt.Infix

let src =
  let src = Logs.Src.create "test" ~doc:"Test the slirp stack" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Dns_policy = struct
  let config_of_ips ips =
    let open Dns_forward.Config in
    let servers =
      Server.Set.of_list (
        List.map (fun (ip, _) ->
            { Server.address = { Address.ip; port = 53 };
              zones = Domain.Set.empty;
              timeout_ms = Some 2000; order = 0 }
          ) ips)
    in
    { servers; search = []; assume_offline_after_drops = None }

  module Config = Hostnet_dns.Config

  let google_dns =
    let ips = [
      Ipaddr.of_string_exn "8.8.8.8", 53;
      Ipaddr.of_string_exn "8.8.4.4", 53;
    ] in
    `Upstream (config_of_ips ips)

  type priority = int

  module IntMap =
    Map.Make(struct
      type t = int let
      compare (a: int) (b: int) = Stdlib.compare a b
    end)

  let t = ref (IntMap.add 0 google_dns IntMap.empty)

  let clear () = t := (IntMap.add 0 google_dns IntMap.empty)

  let config () =
    snd @@ IntMap.max_binding !t

  let add ~priority ~config:c =
    let before = config () in
    t := IntMap.add priority c (!t);
    let after = config () in
    if Config.compare before after <> 0
    then Log.info (fun f ->
        f "Add(%d): DNS configuration changed to: %s" priority
          (Config.to_string after))

  let remove ~priority =
    let before = config () in
    t := IntMap.remove priority !t;
    let after = config () in
    if Config.compare before after <> 0
    then Log.info (fun f ->
        f "Remove(%d): DNS configuration changed to: %s" priority
          (Config.to_string after))

end

module VMNET = Vmnet.Make(Host.Sockets.Stream.Tcp)
module Vnet = Basic_backend.Make
module Slirp_stack =
  Slirp.Make(VMNET)(Dns_policy)(Mclock)(Stdlibrandom)(Vnet)

module Client = struct
  module Netif = VMNET
  module Ethif1 = Ethif.Make(Netif)
  module Arpv41 = Arpv4.Make(Ethif1)(Mclock)(Host.Time)

  module Dhcp_client_mirage1 = Dhcp_client_mirage.Make(Host.Time)(Netif)
  module Ipv41 = Dhcp_ipv4.Make(Dhcp_client_mirage1)(Ethif1)(Arpv41)
  module Icmpv41 = struct
    include Icmpv4.Make(Ipv41)
    let packets = Queue.create ()
    let input _ ~src ~dst buf =
      match Icmpv4_packet.Unmarshal.of_cstruct buf with
      | Error msg ->
        Log.err (fun f -> f "Error unmarshalling ICMP message: %s" msg);
        Lwt.return_unit
      | Ok (reply, _) ->
        let open Icmpv4_packet in
        begin match reply.subheader with
          | Next_hop_mtu _ | Pointer _ | Address _ | Unused ->
            Log.err (fun f -> f "received an ICMP message which wasn't an echo-request or reply");
            Lwt.return_unit
          | Id_and_seq (id, _) ->
            Log.info (fun f ->
              f "ICMP src:%a dst:%a id:%d" Ipaddr.V4.pp src Ipaddr.V4.pp dst id);
              Queue.push (src, dst, id) packets;
              Lwt.return_unit
        end
  end
  module Udp1 = Udp.Make(Ipv41)(Stdlibrandom)
  module Tcp1 = Tcp.Flow.Make(Ipv41)(Host.Time)(Mclock)(Stdlibrandom)
  include Tcpip_stack_direct.Make(Host.Time)
      (Stdlibrandom)(Netif)(Ethif1)(Arpv41)(Ipv41)(Icmpv41)(Udp1)(Tcp1)

  let or_error name m =
    m >>= function
    | `Error _ -> Fmt.kstrf failwith "Failed to connect %s device" name
    | `Ok x    -> Lwt.return x

  type stack = {
    t: t;
    icmpv4: Icmpv41.t;
    netif: VMNET.t;
  }

  let connect (interface: VMNET.t) =
    Ethif1.connect interface >>= fun ethif ->
    Mclock.connect () >>= fun clock ->
    Arpv41.connect ethif clock >>= fun arp ->
    Dhcp_client_mirage1.connect interface >>= fun dhcp ->
    Ipv41.connect dhcp ethif arp >>= fun ipv4 ->
    Icmpv41.connect ipv4 >>= fun icmpv4 ->
    Udp1.connect ipv4 >>= fun udp4 ->
    Tcp1.connect ipv4 clock >>= fun tcp4 ->
    let cfg = {
      Mirage_stack_lwt.name = "stackv4_ip";
      interface;
    } in
    connect cfg ethif arp ipv4 icmpv4 udp4 tcp4
    >>= fun t ->
    Log.info (fun f -> f "Client has connected");
    Lwt.return { t; icmpv4 ; netif=interface }
end

module DNS = Dns_resolver_mirage.Make(Host.Time)(Client)

let primary_dns_ip = Ipaddr.V4.of_string_exn "192.168.65.1"

let localhost_ip = Ipaddr.V4.of_string_exn "192.168.65.2"

let preferred_ip1 = Ipaddr.V4.of_string_exn "192.168.65.250"

let names_for_localhost = List.map Dns.Name.of_string [ "name1.for.localhost"; "name2.for.localhost" ]

let local_tcpv4_forwarded_port = 8888

let config =
  let configuration = {
    Configuration.default with
    domain = Some "local";
    host_names = names_for_localhost;
    tcpv4_forwards = [ {
      protocol = Tcp;
      external_port = local_tcpv4_forwarded_port;
      internal_ip = Ipaddr.V4.localhost;
      internal_port = local_tcpv4_forwarded_port;
    } ];
  } in
  Mclock.connect () >>= fun clock ->
  let vnet = Vnet.create () in
  Slirp_stack.create_static clock vnet configuration

(* This is a hacky way to get a hancle to the server side of the stack. *)
let slirp_stack = ref None
let slirp_stack_c = Lwt_condition.create ()

let rec get_slirp_stack () =
  match !slirp_stack with
  | None   -> Lwt_condition.wait slirp_stack_c >>= get_slirp_stack
  | Some x -> Lwt.return x

let set_slirp_stack c =
  slirp_stack := Some c;
  Lwt_condition.signal slirp_stack_c ()

let start_stack config () =
  Host.Sockets.Stream.Tcp.bind (Ipaddr.V4 Ipaddr.V4.localhost, 0)
  >>= fun server ->
  Host.Sockets.Stream.Tcp.getsockname server
  >|= fun (_, port) ->
  Log.info (fun f -> f "Bound vpnkit server to localhost:%d" port);
  Host.Sockets.Stream.Tcp.listen server (fun flow ->
      Log.info (fun f -> f "Server connecting   TCP/IP stack");
      Slirp_stack.connect config flow  >>= fun stack ->
      Log.info (fun f -> f "Server connected    TCP/IP stack");
      set_slirp_stack stack;
      Slirp_stack.after_disconnect stack >|= fun () ->
      Log.info (fun f -> f "Server disconnected TCP/IP stack")
    );
  server, port

let stop_stack server =
  Log.info (fun f -> f "Shutting down slirp stack");
  Host.Sockets.Stream.Tcp.shutdown server

let pcap_dir = "./_pcap/"

let with_stack ?uuid ?preferred_ip ~pcap f =
  config >>= fun config ->
  start_stack config ()
  >>= fun (server, port) ->
  Log.info (fun f -> f "Connecting to vpnkit server on localhost:%d" port);
  Host.Sockets.Stream.Tcp.connect (Ipaddr.V4 Ipaddr.V4.localhost, port)
  >>= function
  | Error (`Msg x) -> failwith x
  | Ok flow ->
    Log.info (fun f -> f "Connected  to vpnkit server on localhost:%d" port);
    let server_macaddr = Configuration.default_server_macaddr in
    let uuid =
      match uuid, Uuidm.of_string "d1d9cd61-d0dc-4715-9bb3-4c11da7ad7a5" with
      | Some x, Some _ -> x
      | None, Some x -> x
      | _, None -> failwith "unable to parse test uuid"
    in
    VMNET.client_of_fd ~uuid ?preferred_ip:preferred_ip ~server_macaddr:server_macaddr flow
    >>= function
    | Error (`Msg x ) ->
      (* Server will close when it gets EOF *)
      Host.Sockets.Stream.Tcp.close flow >>= fun () ->
      failwith x
    | Ok client' ->
      Log.info (fun f -> f "Client has established an ethernet link with the vpnkit server");
      (try Unix.mkdir pcap_dir 0o0755 with Unix.Unix_error(Unix.EEXIST, _, _) -> ());
      VMNET.start_capture client' (pcap_dir ^ pcap)
      >>= fun () ->
      Lwt.finalize (fun () ->
          Log.info (fun f -> f "Client connecting TCP/IP stack");
          Client.connect client' >>= fun client ->
          Log.info (fun f -> f "Client connected  TCP/IP stack");
          get_slirp_stack () >>= fun slirp_stack ->
          Log.info (fun f -> f "Calling test case with client and server stack handles");
          f slirp_stack client
        ) (fun () ->
          (* Server will close when it gets EOF *)
          VMNET.disconnect client'
          >>= fun () ->
          stop_stack server
        )

open Lwt.Infix

let src =
  let src = Logs.Src.create "tcpip" ~doc:"Mirage TCP/IP" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Make(Vmnet: Sig.VMNET)(Time: V1_LWT.TIME) = struct

type configuration = {
  local_ip: Ipaddr.V4.t;
  peer_ip: Ipaddr.V4.t;
  extra_dns_ip: Ipaddr.V4.t list;
  prefix: Ipaddr.V4.Prefix.t;
  client_macaddr: Macaddr.t;
  server_macaddr: Macaddr.t;
  get_dhcp_configuration : unit -> Dhcp_server.Config.t;
}

(* Compute the smallest IPv4 network which includes both [a_ip]
   and all [other_ips]. *)
let rec smallest_prefix a_ip other_ips = function
  | 0 -> Ipaddr.V4.Prefix.global
  | bits ->
    let prefix = Ipaddr.V4.Prefix.make bits a_ip in
    if List.for_all (fun b_ip -> Ipaddr.V4.Prefix.mem b_ip prefix) other_ips
    then prefix
    else smallest_prefix a_ip other_ips (bits - 1)

let maximum_ip = function
  | [] -> Ipaddr.V4.of_string_exn "0.0.0.0"
  | hd::tl -> List.fold_left (fun acc x -> if compare acc x > 0 then acc else x) hd tl

(* given some MACs and IPs, construct a usable DHCP configuration *)
let make ~client_macaddr ~server_macaddr ~peer_ip ~local_ip ~extra_dns_ip ~get_domain_search =
  let open Dhcp_server.Config in
  (* FIXME: We need a DHCP range to make the DHCP server happy, even though we
     intend only to serve IPs to one downstream host.
     see https://github.com/haesbaert/charrua-core/issues/27 - this may be
     resolved in the future *)
  let low_ip, high_ip =
    let open Ipaddr.V4 in
    let all_static_ips = local_ip :: peer_ip :: extra_dns_ip in
    let highest = maximum_ip all_static_ips in
    let i32 = to_int32 highest in
    of_int32 @@ Int32.succ i32, of_int32 @@ Int32.succ @@ Int32.succ i32 in
  let prefix = smallest_prefix peer_ip [ local_ip; low_ip; high_ip ] 32 in
  let get_dhcp_configuration () : Dhcp_server.Config.t =
    (* The domain search is encoded using the scheme used for DNS names *)
    let domain_search =
      let open Dns in
      let buffer = Cstruct.create 1024 in
      let _, n, _ = List.fold_left (fun (map, n, buffer) name ->
        Name.marshal map n buffer (Name.of_string name)
      ) (Name.Map.empty, 0, buffer) (get_domain_search ()) in
      Cstruct.(to_string (sub buffer 0 n)) in
    let options = [
      Dhcp_wire.Domain_name "local";
      Dhcp_wire.Routers [ local_ip ];
      Dhcp_wire.Dns_servers (local_ip :: extra_dns_ip);
      Dhcp_wire.Ntp_servers [ local_ip ];
      Dhcp_wire.Broadcast_addr (Ipaddr.V4.Prefix.broadcast prefix);
      Dhcp_wire.Subnet_mask (Ipaddr.V4.Prefix.netmask prefix);
      Dhcp_wire.Domain_search domain_search;
    ] in {
      options = options;
      hostname = "vpnkit"; (* it's us! *)
      hosts = [ ];
      default_lease_time = Int32.of_int (60 * 60 * 2); (* 2 hours, from charrua defaults *)
      max_lease_time = Int32.of_int (60 * 60 * 24) ; (* 24 hours, from charrua defaults *)
      ip_addr = local_ip;
      mac_addr = server_macaddr;
      network = prefix;
      (* FIXME: this needs https://github.com/haesbaert/charrua-core/pull/31 *)
      range = (peer_ip, peer_ip); (* allow one dynamic client *)
    } in
  { peer_ip; local_ip; extra_dns_ip; prefix; server_macaddr; client_macaddr; get_dhcp_configuration }

module Filteredif = Filter.Make(Vmnet)

module Netif = Capture.Make(Filteredif)

module Ethif1 = Ethif.Make(Netif)

module Arpv41 = Arp.Make(Ethif1)

module Ipv41 = Ipv4.Make(Ethif1)(Arpv41)

module Udp1 = Udp.Make(Ipv41)

module Tcp1 = Tcp.Flow.Make(Ipv41)(Time)(Clock)(Random)

include Tcpip_stack_direct.Make(Console_unix)(Time)
    (Random)(Netif)(Ethif1)(Arpv41)(Ipv41)(Udp1)(Tcp1)

module Dhcp = struct
  let of_interest mac dest =
    Macaddr.compare dest mac = 0 || not (Macaddr.is_unicast dest)

  (* With a short lease time we try to avoid spamming the logs with DHCP
     messages. *)
  let logged_bootrequest = ref false
  let logged_bootreply = ref false

  let input net (config : Dhcp_server.Config.t) database buf =
    let open Dhcp_server in
    match (Dhcp_wire.pkt_of_buf buf (Cstruct.len buf)) with
    | `Error e ->
      Log.err (fun f -> f "failed to parse DHCP packet: %s" e);
      Lwt.return database
    | `Ok pkt ->
      match (Input.input_pkt config database pkt (Clock.time ())) with
      | Input.Silence -> Lwt.return database
      | Input.Update database ->
        Log.debug (fun f -> f "lease database updated");
        Lwt.return database
      | Input.Warning w ->
        Log.warn (fun f -> f "%s" w);
        Lwt.return database
      | Input.Error e ->
        Log.err (fun f -> f "%s" e);
        Lwt.return database
      | Input.Reply (reply, database) ->
        let open Dhcp_wire in
        if pkt.op <> Dhcp_wire.BOOTREQUEST || not !logged_bootrequest
        then Log.info (fun f -> f "%s from %s" (op_to_string pkt.op) (Macaddr.to_string (pkt.srcmac)));
        logged_bootrequest := !logged_bootrequest || (pkt.op = Dhcp_wire.BOOTREQUEST);
        Netif.write net (Dhcp_wire.buf_of_pkt reply)
        >>= fun () ->
        let domain = List.fold_left (fun acc x -> match x with
          | Domain_name y -> y
          | _ -> acc) "unknown" reply.options in
        let dns = List.fold_left (fun acc x -> match x with
          | Dns_servers ys -> String.concat ", " (List.map Ipaddr.V4.to_string ys)
          | _ -> acc) "none" reply.options in
        let routers = List.fold_left (fun acc x -> match x with
          | Routers ys -> String.concat ", " (List.map Ipaddr.V4.to_string ys)
          | _ -> acc) "none" reply.options in
        if reply.op <> Dhcp_wire.BOOTREPLY || not !logged_bootreply
        then Log.info (fun f -> f "%s to %s yiddr %s siddr %s dns %s router %s domain %s"
          (op_to_string reply.op) (Macaddr.to_string (reply.dstmac))
          (Ipaddr.V4.to_string reply.yiaddr) (Ipaddr.V4.to_string reply.siaddr)
          dns routers domain
        );
        logged_bootreply := !logged_bootreply || (reply.op = Dhcp_wire.BOOTREPLY);
        Lwt.return database

  let listen mac config net buf =
    (* TODO: the scope of this reference ensures that the database won't
       actually remain updated after any particular transaction.  In our case
       that's OK, because we only really want to serve one pre-allocated IP
       anyway, but this will present a problem if that assumption ever changes.  *)
    let database = ref (Dhcp_server.Lease.make_db ()) in
    match (Wire_structs.parse_ethernet_frame buf) with
    | Some (proto, dst, _payload) when of_interest mac dst ->
      (match proto with
       | Some Wire_structs.IPv4 ->
         if Dhcp_wire.is_dhcp buf (Cstruct.len buf) then begin
           input net (config.get_dhcp_configuration ()) !database buf >>= fun db ->
           database := db;
           Lwt.return_unit
         end
         else
           Lwt.return_unit
       | _ -> Lwt.return_unit)
    | _ -> Lwt.return_unit
end

module Infix = struct
  let ( >>= ) m f = m >>= function
    | `Ok x -> f x
    | `Error x -> Lwt.return (`Error x)
end

let or_error name m =
  m >>= function
  | `Error _ -> Lwt.return (`Error (`Msg (Printf.sprintf "Failed to connect %s device" name)))
  | `Ok x -> Lwt.return (`Ok x)

let connect ~config (ppp: Vmnet.t) =
  let open Infix in
  let valid_subnets = [ config.prefix ] in
  let valid_sources = [ Ipaddr.V4.of_string_exn "0.0.0.0" ] in
  let arp_table = [
    config.peer_ip, config.client_macaddr;
    config.local_ip, config.server_macaddr;
  ] @ (List.map (fun ip -> ip, config.server_macaddr) config.extra_dns_ip) in
  or_error "filter" @@ Filteredif.connect ~valid_subnets ~valid_sources ppp
  >>= fun filteredif ->
  or_error "capture" @@ Netif.connect ~limit:1048576 filteredif
  >>= fun interface ->
  or_error "console" @@ Console_unix.connect "0"
  >>= fun console ->
  or_error "ethernet" @@ Ethif1.connect interface
  >>= fun ethif ->
  or_error "arp" @@ Arpv41.connect ~table:arp_table ethif
  >>= fun arp ->
  or_error "ipv4" @@ Ipv41.connect ethif arp
  >>= fun ipv4 ->
  or_error "udp" @@ Udp1.connect ipv4
  >>= fun udp4 ->
  or_error "tcp" @@ Tcp1.connect ipv4
  >>= fun tcp4 ->
  let netmask = Ipaddr.V4.Prefix.netmask config.prefix in
  let cfg = {
    V1_LWT. name = "stackv4_ip";
    console;
    interface;
    mode = `IPv4 (config.local_ip, netmask, []);
  } in
  or_error "stack" @@ connect cfg ethif arp ipv4 udp4 tcp4
  >>= fun stack ->

  Lwt_list.fold_left_s
    (fun acc ip ->
      Lwt.return acc >>= fun acc ->
      or_error "dns_ipv4" @@ Ipv41.connect ~ip ~netmask ethif arp
      >>= fun dns_ipv4 ->
      or_error "dns_udp" @@ Udp1.connect dns_ipv4
      >>= fun dns_udpv4 ->
      Lwt.return (`Ok (dns_udpv4 :: acc))
    ) (`Ok []) config.extra_dns_ip
  >>= fun udps ->

  (* Hook in the DHCP server too *)
  Netif.add_listener interface (Dhcp.listen config.server_macaddr config interface);
  Lwt.return (`Ok (stack, List.rev udps))

(* FIXME: this is unnecessary, mirage-flow should be changed *)
module TCPV4_half_close = struct
  include TCPV4
  let shutdown_read _flow =
    (* No change to the TCP PCB: all this means is that I've
       got my finders in my ears and am nolonger listening to
       what you say. *)
    Lwt.return ()
  let shutdown_write = close
end
end

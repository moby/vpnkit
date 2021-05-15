open Lwt.Infix

let src =
  let src = Logs.Src.create "dhcp" ~doc:"Mirage TCP/IP" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

(* Global configuration: options, gateway etc *)
let global_dhcp_configuration = ref None

let update_global_configuration x =
    global_dhcp_configuration := x

module Make (Clock: Mirage_clock.MCLOCK) (Netif: Mirage_net.S) = struct

  type t = {
    netif: Netif.t;
    server_macaddr: Macaddr.t;
    get_dhcp_configuration: unit -> Dhcp_server.Config.t;
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
  | hd::tl ->
    List.fold_left (fun acc x -> if compare acc x > 0 then acc else x) hd tl

  (* given some MACs and IPs, construct a usable DHCP configuration *)
  let make ~configuration:c netif =
    let open Dhcp_server.Config in
    (* FIXME: We need a DHCP range to make the DHCP server happy, even though we
       intend only to serve IPs to one downstream host.
       see https://github.com/haesbaert/charrua-core/issues/27 - this may be
       resolved in the future *)
    let low_ip, high_ip =
      let open Ipaddr.V4 in
      let all_static_ips = [ c.Configuration.gateway_ip; c.Configuration.lowest_ip ] in
      let highest = maximum_ip all_static_ips in
      let i32 = to_int32 highest in
      of_int32 @@ Int32.succ i32, of_int32 @@ Int32.succ @@ Int32.succ i32 in
    let ip_list = [ c.Configuration.gateway_ip; low_ip; high_ip; c.Configuration.highest_ip ] in
    let prefix = smallest_prefix c.Configuration.lowest_ip ip_list 32 in
    (* Use the dhcp.json in preference, otherwise fall back to the DNS configuration *)
    let domain_search = match !global_dhcp_configuration with
      | Some { Configuration.Dhcp_configuration.searchDomains = domain_search; _ } when domain_search <> [] -> domain_search
      | _ -> c.dns.Dns_forward.Config.search in
    let get_dhcp_configuration () =
      (* The domain search is encoded using the scheme used for DNS names *)
      let domain_search =
        let open Dns in
        let buffer = Cstruct.create 1024 in
        let _, n, _ = List.fold_left (fun (map, n, buffer) name ->
            Name.marshal map n buffer (Name.of_string name)
          ) (Name.Map.empty, 0, buffer) domain_search in
        Cstruct.(to_string (sub buffer 0 n)) in
      (* Use the domainName from the command-line if present, otherwise use the
          dhcp.json file *)
      let domain_name = match c.Configuration.domain, !global_dhcp_configuration with
        | Some domain_name, _ -> domain_name
        | None, Some { Configuration.Dhcp_configuration.domainName = Some domain_name; _ } -> domain_name
        | _, _ -> Configuration.default_domain in
      let options = [
        Dhcp_wire.Routers [ c.Configuration.gateway_ip ];
        Dhcp_wire.Dns_servers [ c.Configuration.gateway_ip ];
        Dhcp_wire.Ntp_servers [ c.Configuration.gateway_ip ];
        Dhcp_wire.Broadcast_addr (Ipaddr.V4.Prefix.broadcast prefix);
        Dhcp_wire.Subnet_mask (Ipaddr.V4.Prefix.netmask prefix);
      ] in
      (* domain_search and get_domain_name may produce an empty string, which is
        * invalid, so only add the option if there is content *)
      let options = if domain_search = "" then options
        else Dhcp_wire.Domain_search domain_search :: options in
      let options = if domain_name = "" then options
        else Dhcp_wire.Domain_name domain_name :: options in
      {
        options = options;
        hostname = "vpnkit"; (* it's us! *)
        hosts = [ ];
        (* 2 hours, from charrua defaults *)
        default_lease_time = Int32.of_int (60 * 60 * 2);
        (* 24 hours, from charrua defaults *)
        max_lease_time = Int32.of_int (60 * 60 * 24) ;
        ip_addr = c.Configuration.gateway_ip;
        mac_addr = c.Configuration.server_macaddr;
        network = prefix;
        (* FIXME: this needs https://github.com/haesbaert/charrua-core/pull/31 *)
        range = Some (c.Configuration.lowest_ip, c.Configuration.lowest_ip); (* allow one dynamic client *)
      } in

    { server_macaddr = c.Configuration.server_macaddr; get_dhcp_configuration; netif }

  let of_interest mac dest =
    Macaddr.compare dest mac = 0 || not (Macaddr.is_unicast dest)

  (* With a short lease time we try to avoid spamming the logs with DHCP
     messages. *)
  let logged_bootrequest = ref false
  let logged_bootreply = ref false

  let input net (config : Dhcp_server.Config.t) database buf =
    let open Dhcp_server in
    match Dhcp_wire.pkt_of_buf buf (Cstruct.len buf) with
    | Error e ->
      Log.err (fun f -> f "failed to parse DHCP packet: %s" e);
      Lwt.return database
    | Ok pkt ->
      let elapsed_seconds =
        Clock.elapsed_ns ()
        |> Duration.to_sec
        |> Int32.of_int
      in
      match Input.input_pkt config database pkt elapsed_seconds with
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
        then Log.info (fun f ->
            f "%s from %s" (op_to_string pkt.op)
              (Macaddr.to_string (pkt.srcmac)));
        logged_bootrequest :=
          !logged_bootrequest || (pkt.op = Dhcp_wire.BOOTREQUEST);
        Netif.write net ~size:1500 (fun buf ->
          Dhcp_wire.pkt_into_buf reply buf
        ) >>= function
        | Error e ->
          Log.err (fun f -> f "failed to parse DHCP reply: %a" Netif.pp_error e);
          Lwt.return database
        | Ok () ->
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
          then Log.info (fun f ->
              f "%s to %s yiddr %a siddr %a dns %s router %s domain %s"
                (op_to_string reply.op) (Macaddr.to_string (reply.dstmac))
                Ipaddr.V4.pp reply.yiaddr Ipaddr.V4.pp reply.siaddr
                dns routers domain
            );
          logged_bootreply :=
            !logged_bootreply || (reply.op = Dhcp_wire.BOOTREPLY);
          Lwt.return database

  let callback t buf =
    (* TODO: the scope of this reference ensures that the database
       won't actually remain updated after any particular transaction.
       In our case that's OK, because we only really want to serve one
       pre-allocated IP anyway, but this will present a problem if
       that assumption ever changes.  *)
    let database = ref (Dhcp_server.Lease.make_db ()) in
    match Ethernet_packet.Unmarshal.of_cstruct buf with
    | Ok (pkt, _payload) when
        of_interest t.server_macaddr pkt.Ethernet_packet.destination ->
      (match pkt.Ethernet_packet.ethertype with
      | `IPv4 ->
        if Dhcp_wire.is_dhcp buf (Cstruct.len buf) then begin
          input t.netif (t.get_dhcp_configuration ()) !database buf
          >|= fun db ->
          database := db
        end
        else
          Lwt.return_unit
      | _ -> Lwt.return_unit)
    | _ -> Lwt.return_unit
end

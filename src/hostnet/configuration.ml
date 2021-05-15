let src =
  let src = Logs.Src.create "configuration" ~doc:"Mirage TCP/IP <-> socket proxy" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let default_domain = "localdomain"

module Dhcp_configuration = struct
  type t = {
    searchDomains: string list;
    domainName: string option;
  }
  let to_string t = Printf.sprintf "{ searchDomains = %s; domainName = %s }"
    (String.concat ", " t.searchDomains)
    (match t.domainName with None -> "None" | Some x -> x)
  let of_string txt =
    let open Ezjsonm in
    begin match from_string txt with
    | exception _ ->
      Log.err (fun f -> f "Failed to parse DHCP configuration json: %s" txt);
      None
    | j ->
      let searchDomains =
        try get_strings @@ find j [ "searchDomains" ]
        with Not_found -> [] in
      let domainName =
        try Some (get_string @@ find j [ "domainName" ])
        with Not_found -> None in
      Some { searchDomains; domainName }
    end
end

type t = {
  server_macaddr: Macaddr.t;
  max_connections: int option;
  dns: Dns_forward.Config.t;
  dns_path: string option;
  resolver: [ `Host | `Upstream ];
  domain: string option;
  allowed_bind_addresses: Ipaddr.V4.t list;
  gateway_ip: Ipaddr.V4.t;
  host_ip: Ipaddr.V4.t;
  (* TODO: remove this from the record since it is not constant across all clients *)
  lowest_ip: Ipaddr.V4.t;
  highest_ip: Ipaddr.V4.t;
  dhcp_json_path: string option;
  dhcp_configuration: Dhcp_configuration.t option;
  mtu: int;
  http_intercept: Ezjsonm.value option;
  http_intercept_path: string option;
  port_max_idle_time: int;
  host_names: Dns.Name.t list;
  gateway_names: Dns.Name.t list;
  vm_names: Dns.Name.t list;
  udpv4_forwards: Gateway_forwards.t;
  tcpv4_forwards: Gateway_forwards.t;
  gateway_forwards_path: string option;
  pcap_snaplen: int;
}

let to_string t =
  Printf.sprintf "server_macaddr = %s; max_connection = %s; dns_path = %s; dns = %s; resolver = %s; domain = %s; allowed_bind_addresses = %s; gateway_ip = %s; host_ip = %s; lowest_ip = %s; highest_ip = %s; dhcp_json_path = %s; dhcp_configuration = %s; mtu = %d; http_intercept = %s; http_intercept_path = %s; port_max_idle_time = %s; host_names = %s; gateway_names = %s; vm_names = %s; udpv4_forwards = %s; tcpv4_forwards = %s; gateway_forwards_path = %s; pcap_snaplen = %d"
    (Macaddr.to_string t.server_macaddr)
    (match t.max_connections with None -> "None" | Some x -> string_of_int x)
    (match t.dns_path with None -> "None" | Some x -> x)
    (Dns_forward.Config.to_string t.dns)
    (match t.resolver with `Host -> "Host" | `Upstream -> "Upstream")
    (match t.domain with None -> "None" | Some x -> x)
    (String.concat ", " (List.map Ipaddr.V4.to_string t.allowed_bind_addresses))
    (Ipaddr.V4.to_string t.gateway_ip)
    (Ipaddr.V4.to_string t.host_ip)
    (Ipaddr.V4.to_string t.lowest_ip)
    (Ipaddr.V4.to_string t.highest_ip)
    (match t.dhcp_json_path with None -> "None" | Some x -> x)
    (match t.dhcp_configuration with None -> "None" | Some x -> Dhcp_configuration.to_string x)
    t.mtu
    (match t.http_intercept with None -> "None" | Some x -> Ezjsonm.(to_string @@ wrap x))
    (match t.http_intercept_path with None -> "None" | Some x -> x)
    (string_of_int t.port_max_idle_time)
    (String.concat ", " (List.map Dns.Name.to_string t.host_names))
    (String.concat ", " (List.map Dns.Name.to_string t.gateway_names))
    (String.concat ", " (List.map Dns.Name.to_string t.vm_names))
    (Gateway_forwards.to_string t.udpv4_forwards)
    (Gateway_forwards.to_string t.tcpv4_forwards)
    (match t.gateway_forwards_path with None -> "None" | Some x -> x)
    t.pcap_snaplen

let no_dns_servers =
  Dns_forward.Config.({ servers = Server.Set.empty; search = []; assume_offline_after_drops = None })

let default_lowest_ip = Ipaddr.V4.of_string_exn "192.168.65.3"
let default_gateway_ip = Ipaddr.V4.of_string_exn "192.168.65.1"
let default_host_ip = Ipaddr.V4.of_string_exn "192.168.65.2"
let default_highest_ip = Ipaddr.V4.of_string_exn "192.168.65.254"
(* The default MTU is limited by the maximum message size on a Hyper-V
   socket. On currently available windows versions, we need to stay
   below 8192 bytes *)
let default_mtu = 1500 (* used for the virtual ethernet link *)
let default_port_max_idle_time = 300
(* random MAC from https://www.hellion.org.uk/cgi-bin/randmac.pl *)
let default_server_macaddr = Macaddr.of_string_exn "F6:16:36:BC:F9:C6"
let default_host_names = [ Dns.Name.of_string "vpnkit.host" ]
let default_gateway_names = [ Dns.Name.of_string "gateway.internal" ]
let default_vm_names = [ Dns.Name.of_string "vm.internal" ]
let default_pcap_snaplen = 128

let default_resolver = `Host

let default = {
  server_macaddr = default_server_macaddr;
  max_connections = None;
  dns = no_dns_servers;
  dns_path = None;
  resolver = default_resolver;
  domain = None;
  allowed_bind_addresses = [];
  gateway_ip = default_gateway_ip;
  host_ip = default_host_ip;
  lowest_ip = default_lowest_ip;
  highest_ip = default_highest_ip;
  dhcp_json_path = None;
  dhcp_configuration = None;
  mtu = default_mtu;
  http_intercept = None;
  http_intercept_path = None;
  port_max_idle_time = default_port_max_idle_time;
  host_names = default_host_names;
  gateway_names = default_gateway_names;
  vm_names = default_gateway_names;
  udpv4_forwards = [];
  tcpv4_forwards = [];
  gateway_forwards_path = None;
  pcap_snaplen = default_pcap_snaplen;
}

module Parse = struct

  let ipv4 default x = match Ipaddr.V4.of_string @@ String.trim x with
  | Error (`Msg m) ->
    Log.err (fun f ->
        f "Failed to parse IPv4 address '%s', using default of %a: %s"
          x Ipaddr.V4.pp default m);
    Lwt.return default
  | Ok x -> Lwt.return x

  let ipv4_list default x =
    let all =
      List.map Ipaddr.V4.of_string @@
      List.filter (fun x -> x <> "") @@
      List.map String.trim @@
      Astring.String.cuts ~sep:"," x
    in
    let any_error, ok = List.fold_left (fun (any_error, ok) x -> match x with
      | Error _ -> true, ok
      | Ok x -> any_error, x :: ok
      ) (false, []) all in
    if any_error then begin
      Log.err (fun f ->
          f "Failed to parse IPv4 address list '%s', using default of %s" x
            (String.concat "," (List.map Ipaddr.V4.to_string default)));
      default
    end else ok

  let int = function
  | None -> Lwt.return None
  | Some x -> Lwt.return (
      try Some (int_of_string @@ String.trim x)
      with _ ->
        Log.err (fun f ->
            f "Failed to parse integer value: '%s'" x);
        None
    )

  let resolver = function
  | Some "host" -> Lwt.return `Host
  | _ -> Lwt.return `Upstream

  let dns txt =
    let open Dns_forward in
    begin match Config.of_string txt with
    | Ok config -> Some config
    | Error (`Msg m) ->
      Log.err (fun f -> f "failed to parse dns configuration: %s" m);
      None
    end

end
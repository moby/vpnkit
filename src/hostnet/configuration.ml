let src =
  let src = Logs.Src.create "configuration" ~doc:"Mirage TCP/IP <-> socket proxy" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

type t = {
  server_macaddr: Macaddr.t;
  max_connections: int option;
  dns: Dns_forward.Config.t;
  dns_path: string option;
  resolver: [ `Host | `Upstream ];
  domain: string;
  allowed_bind_addresses: Ipaddr.V4.t list;
  gateway_ip: Ipaddr.V4.t;
  (* TODO: remove this from the record since it is not constant across all clients *)
  peer: Ipaddr.V4.t;
  highest_ip: Ipaddr.V4.t;
  extra_dns: Ipaddr.V4.t list;
  mtu: int;
  http_intercept: Ezjsonm.value option;
  port_max_idle_time: int;
  host_names: Dns.Name.t list;
}

let to_string t =
  Printf.sprintf "server_macaddr = %s; max_connection = %s; dns_path = %s; dns = %s; resolver = %s; domain = %s; allowed_bind_addresses = %s; gateway_ip = %s; peer = %s; highest_ip = %s; extra_dns = %s; mtu = %d; http_intercept = %s; port_max_idle_time = %s; host_names = %s"
    (Macaddr.to_string t.server_macaddr)
    (match t.max_connections with None -> "None" | Some x -> string_of_int x)
    (match t.dns_path with None -> "None" | Some x -> x)
    (Dns_forward.Config.to_string t.dns)
    (match t.resolver with `Host -> "Host" | `Upstream -> "Upstream")
    t.domain
    (String.concat ", " (List.map Ipaddr.V4.to_string t.allowed_bind_addresses))
    (Ipaddr.V4.to_string t.gateway_ip)
    (Ipaddr.V4.to_string t.peer)
    (Ipaddr.V4.to_string t.highest_ip)
    (String.concat ", " (List.map Ipaddr.V4.to_string t.extra_dns))
    t.mtu
    (match t.http_intercept with None -> "None" | Some x -> Ezjsonm.(to_string @@ wrap x))
    (string_of_int t.port_max_idle_time)
    (String.concat ", " (List.map Dns.Name.to_string t.host_names))

let no_dns_servers =
  Dns_forward.Config.({ servers = Server.Set.empty; search = []; assume_offline_after_drops = None })

let default_peer = Ipaddr.V4.of_string_exn "192.168.65.2"
let default_gateway_ip = Ipaddr.V4.of_string_exn "192.168.65.1"
let default_highest_ip = Ipaddr.V4.of_string_exn "192.168.65.254"
let default_extra_dns = []
(* The default MTU is limited by the maximum message size on a Hyper-V
   socket. On currently available windows versions, we need to stay
   below 8192 bytes *)
let default_mtu = 1500 (* used for the virtual ethernet link *)
let default_port_max_idle_time = 300
(* random MAC from https://www.hellion.org.uk/cgi-bin/randmac.pl *)
let default_server_macaddr = Macaddr.of_string_exn "F6:16:36:BC:F9:C6"
let default_host_names = [ Dns.Name.of_string "vpnkit.host" ]
let default_resolver = `Host
let default_domain = "localdomain"

let default = {
  server_macaddr = default_server_macaddr;
  max_connections = None;
  dns = no_dns_servers;
  dns_path = None;
  resolver = default_resolver;
  domain = default_domain;
  allowed_bind_addresses = [];
  gateway_ip = default_gateway_ip;
  peer = default_peer;
  highest_ip = default_highest_ip;
  extra_dns = default_extra_dns;
  mtu = default_mtu;
  http_intercept = None;
  port_max_idle_time = default_port_max_idle_time;
  host_names = default_host_names;
}

module Parse = struct

  let ipv4 default x = match Ipaddr.V4.of_string @@ String.trim x with
  | None ->
    Log.err (fun f ->
        f "Failed to parse IPv4 address '%s', using default of %a"
          x Ipaddr.V4.pp_hum default);
    Lwt.return default
  | Some x -> Lwt.return x

  let ipv4_list default x =
    let all =
      List.map Ipaddr.V4.of_string @@
      List.filter (fun x -> x <> "") @@
      List.map String.trim @@
      Astring.String.cuts ~sep:"," x
    in
    let any_none, some = List.fold_left (fun (any_none, some) x -> match x with
      | None -> true, some
      | Some x -> any_none, x :: some
      ) (false, []) all in
    if any_none then begin
      Log.err (fun f ->
          f "Failed to parse IPv4 address list '%s', using default of %s" x
            (String.concat "," (List.map Ipaddr.V4.to_string default)));
      default
    end else some

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
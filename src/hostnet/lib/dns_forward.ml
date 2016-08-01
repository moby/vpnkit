open Lwt.Infix

let src =
  let src = Logs.Src.create "dns" ~doc:"Resolve DNS queries on the host" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let parse_dns buf =
  let len = Cstruct.len buf in
  let buf = Dns.Buf.of_cstruct buf in
  (len, Dns.Protocol.Server.parse (Dns.Buf.sub buf 0 len))

let string_of_dns dns =
  match dns with
  | (len, None) ->
    Printf.sprintf "Unparsable DNS packet length %d" len
  | (_, Some request) ->
    Dns.Packet.to_string request

let tidstr_of_dns dns =
  match dns with
  | (_, None) -> "----"
  | (_, Some { Dns.Packet.id; _ }) -> Printf.sprintf "%04x" id

let only_ipv4 servers =
  List.filter (function
    | Ipaddr.V4 _, _ -> true
    | _ -> false
  ) servers

module Make(Ip: V1_LWT.IPV4) (Udp:V1_LWT.UDPV4) (Resolv_conf: Sig.RESOLV_CONF) (Socket: Sig.SOCKETS) (Time: V1_LWT.TIME) = struct

let input ~secondary ~ip ~udp ~src ~dst ~src_port buf =
  if List.mem dst (Ip.get_ip ip) then begin

  let src_str = Ipaddr.V4.to_string src in
  let dst_str = Ipaddr.V4.to_string dst in

  let dns = parse_dns buf in

  Log.debug (fun f -> f "DNS[%s] %s:%d -> %s %s" (tidstr_of_dns dns) src_str src_port dst_str (string_of_dns dns));

  Resolv_conf.get ()
  >>= fun all ->
  ( match only_ipv4 all with
  | _::sec::_ when secondary -> Lwt.return_some ("secondary", sec)
  | pri::_::_ when not secondary -> Lwt.return_some ("primary", pri)
  (* These two could be collapsed, but for the desire to differentiate in the logging *)
  | pri::_ when secondary -> Lwt.return_some ("secondary(wrapped)", pri)
  | pri::_ when not secondary -> Lwt.return_some ("primary(sole)", pri)
  | _ -> Lwt.return_none )

  >>= function
  | Some (dst_str, (dst, dst_port)) ->
    Log.debug (fun f -> f "DNS[%s] Forwarding to %s (%s)" (tidstr_of_dns dns) (Ipaddr.to_string dst) dst_str);
    let reply buffer =
      Log.debug (fun f -> f "DNS[%s] %s:%d <- %s (%s)" (tidstr_of_dns dns) src_str src_port dst_str (string_of_dns (parse_dns buffer)));
      Udp.write ~source_port:53 ~dest_ip:src ~dest_port:src_port udp buffer in
    let userdesc = "DNS[" ^ (tidstr_of_dns dns) ^ "]" in
    Socket.Datagram.input ~userdesc ~reply ~src:(Ipaddr.V4 src, src_port) ~dst:(dst, dst_port) ~payload:buf ()
  | None ->
    Log.err (fun f -> f "DNS[%s] No upstream DNS server configured: dropping request" (tidstr_of_dns dns));
    Lwt.return_unit
  end else Lwt.return_unit
end

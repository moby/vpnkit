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

let choose_server ~nth all =
  let l = List.length all in
  let suffix = if nth > l then "(wrapped)" else "" in
  if all = []
  then None
  else Some (string_of_int nth ^ suffix, List.nth (only_ipv4 all) (nth mod l))

let lookup_locally = function
  | _, Some request ->
    let open Dns.Packet in
    begin match request with
    | { id; detail; additionals; questions = [ { q_class = Q_IN; q_type = Q_A; q_name; _ } ]; _ } ->
      begin match List.fold_left (fun found (name, ip) -> match found, ip with
        | Some v4, _           -> Some v4
        | None,   Ipaddr.V4 v4 ->
          if Dns.Name.to_string q_name = name then Some v4 else None
        | None,   Ipaddr.V6 _  -> None
      ) None !(Hosts.etc_hosts) with
      | None -> None
      | Some v4 ->
        Log.debug (fun f -> f "DNS[%04x] %s is %s in in /etc/hosts" id (Dns.Name.to_string q_name) (Ipaddr.V4.to_string v4));
        let answers = [ { name = q_name; cls = RR_IN; flush = false; ttl = 0l; rdata = A v4 } ] in
        Some { Dns.Packet.id; detail; questions = request.questions; authorities=[]; additionals; answers }
      end
    | { id; detail; additionals; questions = [ { q_class = Q_IN; q_type = Q_AAAA; q_name; _ } ]; _ } ->
      begin match List.fold_left (fun found (name, ip) -> match found, ip with
        | Some v6, _           -> Some v6
        | None,   Ipaddr.V6 v6 ->
          if Dns.Name.to_string q_name = name then Some v6 else None
        | None,   Ipaddr.V4 _  -> None
      ) None !(Hosts.etc_hosts) with
      | None -> None
      | Some v6 ->
        Log.debug (fun f -> f "DNS[%04x] %s is %s in in /etc/hosts" id (Dns.Name.to_string q_name) (Ipaddr.V6.to_string v6));
        let answers = [ { name = q_name; cls = RR_IN; flush = false; ttl = 0l; rdata = AAAA v6 } ] in
        Some { Dns.Packet.id; detail; questions = request.questions; authorities=[]; additionals; answers }
      end
    | _ -> None
    end
  | _, _ -> None

module Make(Ip: V1_LWT.IPV4) (Udp:V1_LWT.UDPV4) (Resolv_conf: Sig.RESOLV_CONF) (Socket: Sig.SOCKETS) (Time: V1_LWT.TIME) = struct

let choose_server ~nth () =
  Resolv_conf.get ()
  >>= fun all ->
  Lwt.return (choose_server ~nth all.Resolver.resolvers)

let input ~nth ~udp ~src ~dst ~src_port buf =
  let src_str = Ipaddr.V4.to_string src in
  let dst_str = Ipaddr.V4.to_string dst in

  let dns = parse_dns buf in

  let reply buffer =
    Log.debug (fun f -> f "DNS[%s] %s:%d <- %s (%s)" (tidstr_of_dns dns) src_str src_port dst_str (string_of_dns (parse_dns buffer)));
    Udp.write ~source_port:53 ~dest_ip:src ~dest_port:src_port udp buffer in

  Log.debug (fun f -> f "DNS[%s] %s:%d -> %s %s" (tidstr_of_dns dns) src_str src_port dst_str (string_of_dns dns));
  (* Is this an A or AAAA query which can be satisfied from /etc/hosts? *)
  match lookup_locally dns with
  | Some response ->
    let obuf = Dns.Buf.create 4096 in
    begin match Dns.Protocol.Server.marshal obuf response response with
    | None ->
      Log.err (fun f -> f "DNS[%s] failed to marshal response" (tidstr_of_dns dns));
      Lwt.return_unit
    | Some buf ->
      let buf = Cstruct.of_bigarray buf in
      reply buf
    end
  | None ->
    choose_server ~nth ()
    >>= function
    | Some (dst_str, (dst, dst_port)) ->
      Log.debug (fun f -> f "DNS[%s] Forwarding to %s (%s)" (tidstr_of_dns dns) (Ipaddr.to_string dst) dst_str);
      let reply buffer =
        Log.debug (fun f -> f "DNS[%s] %s:%d <- %s (%s)" (tidstr_of_dns dns) src_str src_port dst_str (string_of_dns (parse_dns buffer)));
        Udp.write ~source_port:53 ~dest_ip:src ~dest_port:src_port udp buffer in
      let userdesc = "DNS[" ^ (tidstr_of_dns dns) ^ "]" in
      Socket.Datagram.input ~userdesc ~oneshot:true ~reply ~src:(Ipaddr.V4 src, src_port) ~dst:(dst, dst_port) ~payload:buf ()
    | None ->
      Log.err (fun f -> f "DNS[%s] No upstream DNS server configured: dropping request" (tidstr_of_dns dns));
      Lwt.return_unit
end

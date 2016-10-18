open Lwt.Infix

let src =
  let src = Logs.Src.create "dns" ~doc:"Resolve DNS queries on the host" in
  Logs.Src.set_level src (Some Logs.Info);
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
        Log.info (fun f -> f "DNS[%04x] %s is %s in in /etc/hosts" id (Dns.Name.to_string q_name) (Ipaddr.V4.to_string v4));
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
        Log.info (fun f -> f "DNS[%04x] %s is %s in in /etc/hosts" id (Dns.Name.to_string q_name) (Ipaddr.V6.to_string v6));
        let answers = [ { name = q_name; cls = RR_IN; flush = false; ttl = 0l; rdata = AAAA v6 } ] in
        Some { Dns.Packet.id; detail; questions = request.questions; authorities=[]; additionals; answers }
      end
    | _ -> None
    end
  | _, _ -> None

module Make(Ip: V1_LWT.IPV4) (Udp:V1_LWT.UDPV4) (Resolv_conf: Sig.RESOLV_CONF) (Socket: Sig.SOCKETS) (Time: V1_LWT.TIME) (Recorder: Sig.RECORDER) = struct

let choose_server ~nth () =
  Resolv_conf.get ()
  >>= fun all ->
  Lwt.return (choose_server ~nth all.Resolver.resolvers)

let record_udp ~source_ip ~source_port ~dest_ip ~dest_port ~recorder bufs =
  (* This is from mirage-tcpip-- ideally we would use a simpler packet creation fn *)
  let frame = Io_page.to_cstruct (Io_page.get 1) in
  let smac = "\000\000\000\000\000\000" in
  Wire_structs.set_ethernet_src smac 0 frame;
  Wire_structs.set_ethernet_ethertype frame 0x0800;
  let buf = Cstruct.shift frame Wire_structs.sizeof_ethernet in
  Wire_structs.Ipv4_wire.set_ipv4_hlen_version buf ((4 lsl 4) + (5));
  Wire_structs.Ipv4_wire.set_ipv4_tos buf 0;
  Wire_structs.Ipv4_wire.set_ipv4_off buf 0;
  Wire_structs.Ipv4_wire.set_ipv4_ttl buf 38;
  let proto = Wire_structs.Ipv4_wire.protocol_to_int `UDP in
  Wire_structs.Ipv4_wire.set_ipv4_proto buf proto;
  Wire_structs.Ipv4_wire.set_ipv4_src buf (Ipaddr.V4.to_int32 source_ip);
  Wire_structs.Ipv4_wire.set_ipv4_dst buf (Ipaddr.V4.to_int32 dest_ip);
  let header_len = Wire_structs.sizeof_ethernet + Wire_structs.Ipv4_wire.sizeof_ipv4 in

  let frame = Cstruct.set_len frame (header_len + Wire_structs.sizeof_udp) in
  let udp_buf = Cstruct.shift frame header_len in
  Wire_structs.set_udp_source_port udp_buf source_port;
  Wire_structs.set_udp_dest_port udp_buf dest_port;
  Wire_structs.set_udp_length udp_buf (Wire_structs.sizeof_udp + Cstruct.lenv bufs);
  Wire_structs.set_udp_checksum udp_buf 0;
  let csum = Ip.checksum frame (udp_buf :: bufs) in
  Wire_structs.set_udp_checksum udp_buf csum;
  (* Ip.writev *)
  let bufs = frame :: bufs in
  let tlen = Cstruct.lenv bufs - Wire_structs.sizeof_ethernet in
  let dmac = String.make 6 '\000' in
  (* Ip.adjust_output_header *)
  Wire_structs.set_ethernet_dst dmac 0 frame;
  let buf = Cstruct.sub frame Wire_structs.sizeof_ethernet Wire_structs.Ipv4_wire.sizeof_ipv4 in
  (* Set the mutable values in the ipv4 header *)
  Wire_structs.Ipv4_wire.set_ipv4_len buf tlen;
  Wire_structs.Ipv4_wire.set_ipv4_id buf (Random.int 65535); (* TODO *)
  Wire_structs.Ipv4_wire.set_ipv4_csum buf 0;
  let checksum = Tcpip_checksum.ones_complement buf in
  Wire_structs.Ipv4_wire.set_ipv4_csum buf checksum;
  Recorder.record recorder bufs

let input ~nth ~udp ~recorder ~src ~dst ~src_port buf =
  let src_str = Ipaddr.V4.to_string src in
  let dst_str = Ipaddr.V4.to_string dst in
  (* src: the address of the VM
     dst: the address of the DNS server i.e. us
     remote: the address of the upstream DNS server *)

  let dns = parse_dns buf in
  let userdesc = "DNS[" ^ (tidstr_of_dns dns) ^ "]" in

  Log.debug (fun f -> f "%s %s:%d -> %s %s" userdesc src_str src_port dst_str (string_of_dns dns));
  (* Is this an A or AAAA query which can be satisfied from /etc/hosts? *)
  match lookup_locally dns with
  | Some response ->
    let obuf = Dns.Buf.create 4096 in
    begin match Dns.Protocol.Server.marshal obuf response response with
    | None ->
      Log.err (fun f -> f "%s failed to marshal response" userdesc);
      Lwt.return_unit
    | Some buf ->
      let buf = Cstruct.of_bigarray buf in
      Log.debug (fun f -> f "%s %s:%d <- %s (%s)" userdesc src_str src_port dst_str (string_of_dns (parse_dns buf)));
      Udp.write ~source_port:53 ~dest_ip:src ~dest_port:src_port udp buf
    end
  | None ->
    choose_server ~nth ()
    >>= function
    | Some (remote_str, (remote, remote_port)) ->
      Log.debug (fun f -> f "%s Forwarding to %s (%s)" userdesc (Ipaddr.to_string remote) remote_str);
      (* Synthesize UDP packets and add then to the packet capture. This will
         traverse the link to the VM which is unnecessary but DNS is low-bandwidth. *)
      let reply buffer =
        Log.debug (fun f -> f "%s %s:%d <- %s (%s)" userdesc src_str src_port remote_str (string_of_dns (parse_dns buffer)));
        begin match remote with
        | Ipaddr.V4 remote ->
          (* Synthesize a packet from the remote to the host i.e. dst *)
          record_udp ~source_ip:remote ~source_port:remote_port ~dest_ip:dst ~dest_port:remote_port ~recorder [ buffer ]
        | _ -> ()
        end;
        Udp.write ~source_port:53 ~dest_ip:src ~dest_port:src_port udp buffer in

      begin match remote with
      | Ipaddr.V4 remote ->
        record_udp ~source_ip:dst ~source_port:remote_port ~dest_ip:remote ~dest_port:remote_port ~recorder [ buf ]
      | _ -> ()
      end;
      Socket.Datagram.input ~userdesc ~oneshot:true ~reply ~src:(Ipaddr.V4 src, src_port) ~dst:(remote, remote_port) ~payload:buf ()

    | None ->
      Log.err (fun f -> f "%s No upstream DNS server configured: dropping request" userdesc);
      Lwt.return_unit
end

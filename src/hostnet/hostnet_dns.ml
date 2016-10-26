module Lwt_result = Hostnet_lwt_result (* remove when we have later lwt *)

open Lwt.Infix

let src =
  let src = Logs.Src.create "dns" ~doc:"Resolve DNS queries on the host" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Policy(Files: Sig.FILES) = struct
  let config_of_ips ips =
    let open Dns_forward.Config in
    let servers = Server.Set.of_list (
      List.map (fun (ip, port) ->
        { Server.address = { Address.ip; port = 53 }; zones = Domain.Set.empty }
      ) ips) in
    { servers; search = [] }

  module IntMap = Map.Make(struct type t = int let compare (a: int) (b: int) = Pervasives.compare a b end)

  let google_dns =
    let ips = [
      Ipaddr.of_string_exn "8.8.8.8", 53;
      Ipaddr.of_string_exn "8.8.4.4", 53;
    ] in
    config_of_ips ips

  type priority = int

  let t = ref (IntMap.add 0 google_dns IntMap.empty)

  let config () =
    snd @@ IntMap.max_binding !t

  let add ~priority ~config:c =
    let before = config () in
    t := IntMap.add priority c (!t);
    let after = config () in
    if Dns_forward.Config.compare before after <> 0
    then Log.info (fun f -> f "Add(%d): DNS configuration changed to: %s" priority (Dns_forward.Config.to_string after))
  let remove ~priority =
    let before = config () in
    t := IntMap.remove priority !t;
    let after = config () in
    if Dns_forward.Config.compare before after <> 0
    then Log.info (fun f -> f "Remove(%d): DNS configuration changed to: %s" priority (Dns_forward.Config.to_string after))

  (* Watch for the /etc/resolv.file *)
  let resolv_conf = "/etc/resolv.conf"
  let _ =
    match Files.watch_file resolv_conf
      (fun () ->
        Lwt.async
          (fun () ->
            let open Error.Infix in
            Files.read_file resolv_conf
            >>= fun txt ->
            match Dns_forward.Config.Unix.of_resolv_conf txt with
            | Result.Error (`Msg m) ->
              Log.err (fun f -> f "Failed to parse %s: %s" resolv_conf m);
              Lwt_result.return ()
            | Result.Ok config ->
              add ~priority:2 ~config;
              Lwt_result.return ()
          )
      ) with
    | Result.Error (`Msg m) ->
      Log.info (fun f -> f "Cannot watch %s: %s" resolv_conf m)
    | Result.Ok _watch ->
      Log.info (fun f -> f "Will watch %s for changes" resolv_conf)

end

let local_names_cb =
  let open Dns.Packet in
  function
  | { q_class = Q_IN; q_type = Q_A; q_name; _ } ->
    begin match List.fold_left (fun found (name, ip) -> match found, ip with
      | Some v4, _           -> Some v4
      | None,   Ipaddr.V4 v4 ->
        if Dns.Name.to_string q_name = name then Some v4 else None
      | None,   Ipaddr.V6 _  -> None
    ) None !(Hosts.etc_hosts) with
    | None -> Lwt.return_none
    | Some v4 ->
      Log.info (fun f -> f "DNS: %s is %s in in /etc/hosts" (Dns.Name.to_string q_name) (Ipaddr.V4.to_string v4));
      Lwt.return (Some [ { name = q_name; cls = RR_IN; flush = false; ttl = 0l; rdata = A v4 } ])
    end
  | { q_class = Q_IN; q_type = Q_AAAA; q_name; _ } ->
    begin match List.fold_left (fun found (name, ip) -> match found, ip with
      | Some v6, _           -> Some v6
      | None,   Ipaddr.V6 v6 ->
        if Dns.Name.to_string q_name = name then Some v6 else None
      | None,   Ipaddr.V4 _  -> None
    ) None !(Hosts.etc_hosts) with
    | None -> Lwt.return_none
    | Some v6 ->
      Log.info (fun f -> f "DNS: %s is %s in in /etc/hosts" (Dns.Name.to_string q_name) (Ipaddr.V6.to_string v6));
      Lwt.return (Some [ { name = q_name; cls = RR_IN; flush = false; ttl = 0l; rdata = AAAA v6 } ])
    end
  | _ -> Lwt.return_none

module Make(Ip: V1_LWT.IPV4) (Udp:V1_LWT.UDPV4) (Tcp:V1_LWT.TCPV4) (Socket: Sig.SOCKETS) (Time: V1_LWT.TIME) (Recorder: Sig.RECORDER) = struct

  (* DNS uses slightly different protocols over TCP and UDP. We need both a UDP
     and TCP resolver configured to use the upstream servers. We will map UDP
     onto UDP and TCP onto TCP, leaving the client to handle the truncated bit
     and retransmissions. *)
  module Dns_tcp_client = Dns_forward.Rpc.Client.Make(Socket.Stream.Tcp)(Dns_forward.Framing.Tcp(Socket.Stream.Tcp))(Time)
  module Dns_tcp_resolver = Dns_forward.Resolver.Make(Dns_tcp_client)(Time)
  module Dns_udp_client = Dns_forward.Rpc.Client.Make(Socket.Datagram.Udp)(Dns_forward.Framing.Udp(Socket.Datagram.Udp))(Time)
  module Dns_udp_resolver = Dns_forward.Resolver.Make(Dns_udp_client)(Time)

  (* We need to be able to parse the incoming framed TCP messages *)
  module Dns_tcp_framing = Dns_forward.Framing.Tcp(Tcp)

  type t = {
    dns_tcp_resolver: Dns_tcp_resolver.t;
    dns_udp_resolver: Dns_udp_resolver.t;
  }

  let recorder = ref None
  let set_recorder r = recorder := Some r

  let destroy t =
    Dns_tcp_resolver.destroy t.dns_tcp_resolver
    >>= fun () ->
    Dns_udp_resolver.destroy t.dns_udp_resolver

  let record_udp ~source_ip ~source_port ~dest_ip ~dest_port bufs =
    match !recorder with
    | Some recorder ->
      (* This is from mirage-tcpip-- ideally we would use a simpler packet creation fn *)
      let frame = Io_page.to_cstruct (Io_page.get 1) in
      let smac = "\000\000\000\000\000\000" in
      Wire_structs.set_ethernet_src smac 0 frame;
      Wire_structs.set_ethernet_ethertype frame 0x0800;
      let buf = Cstruct.shift frame Wire_structs.sizeof_ethernet in
      Wire_structs.Ipv4_wire.set_ipv4_hlen_version buf ((4 lsl 4) + (5));
      Wire_structs.Ipv4_wire.set_ipv4_tos buf 0;
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
    | None ->
      () (* nowhere to log packet *)

  let create ~local_address config =
    let open Dns_forward.Config.Address in
    let message_cb ?(src = local_address) ?(dst = local_address) ~buf () =
      match src, dst with
      | { ip = Ipaddr.V4 source_ip; port = source_port }, { ip = Ipaddr.V4 dest_ip; port = dest_port } ->
        record_udp ~source_ip ~source_port ~dest_ip ~dest_port [ buf ];
        Lwt.return_unit
      | _ ->
        (* We don't know how to marshal IPv6 yet *)
        Lwt.return_unit in
    Dns_udp_resolver.create ~local_names_cb ~message_cb config
    >>= fun dns_udp_resolver ->
    Dns_tcp_resolver.create ~local_names_cb ~message_cb config
    >>= fun dns_tcp_resolver ->
    Lwt.return { dns_tcp_resolver; dns_udp_resolver }

  let describe buf =
    let len = Cstruct.len buf in
    let buf = Dns.Buf.of_cstruct buf in
    match Dns.Protocol.Server.parse (Dns.Buf.sub buf 0 len) with
    | None -> Printf.sprintf "Unparsable DNS packet length %d" len
    | Some request -> Dns.Packet.to_string request

  let handle_udp ~t ~udp ~src ~dst ~src_port buf =
    (* FIXME: need to record the upstream request *)
    Dns_udp_resolver.answer buf t.dns_udp_resolver
    >>= function
    | Result.Error (`Msg m) ->
      Log.warn (fun f -> f "%s lookup failed: %s" (describe buf) m);
      Lwt.return_unit
    | Result.Ok buffer ->
      (* Synthesize a packet from the remote to the host i.e. dst *)
      record_udp ~source_ip:dst ~source_port:53 ~dest_ip:src ~dest_port:src_port [ buffer ];
      Udp.write ~source_port:53 ~dest_ip:src ~dest_port:src_port udp buffer

  let handle_tcp ~t =
    (* FIXME: need to record the upstream request *)
    let listeners port =
      Log.debug (fun f -> f "DNS TCP handshake complete");
      Some (fun flow ->
        let packets = Dns_tcp_framing.connect flow in
        let rec loop () =
          Dns_tcp_framing.read packets
          >>= function
          | Result.Error _ ->
            Lwt.return_unit
          | Result.Ok request ->
            (* Perform queries in background threads *)
            Lwt.async
              (fun () ->
                Dns_tcp_resolver.answer request t.dns_tcp_resolver
                >>= function
                | Result.Error (`Msg m) ->
                  Log.warn (fun f -> f "%s lookup failed: %s" (describe request) m);
                  Lwt.return_unit
                | Result.Ok buffer ->
                  begin Dns_tcp_framing.write packets buffer
                  >>= function
                  | Result.Error (`Msg m) ->
                    Log.warn (fun f -> f "%s failed to write response: %s" (describe buffer) m);
                    Lwt.return_unit
                  | Result.Ok () ->
                    Lwt.return_unit
                  end
              );
              loop () in
        loop ()
      ) in
    Lwt.return listeners

end

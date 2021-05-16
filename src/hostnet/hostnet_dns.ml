open Lwt.Infix

let src =
  let src = Logs.Src.create "dns" ~doc:"Resolve DNS queries on the host" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

(* Maximum size of a UDP DNS response before we must truncate *)
let max_udp_response = 512

module Config = struct
  type t = [
    | `Upstream of Dns_forward.Config.t
    | `Host
  ]

  let to_string = function
  | `Upstream x -> "use upstream DNS servers " ^ (Dns_forward.Config.to_string x)
  | `Host -> "use host resolver"

  let compare a b = match a, b with
  | `Upstream x, `Upstream y -> Dns_forward.Config.compare x y
  | `Host, `Upstream _ -> -1
  | `Upstream _, `Host -> 1
  | `Host, `Host -> 0
end


module Policy(Files: Sig.FILES) = struct
  let config_of_ips ips =
    let open Dns_forward.Config in
    let servers = Server.Set.of_list (
        List.map (fun (ip, _) ->
            { Server.address = { Address.ip; port = 53 }; zones = Domain.Set.empty;
              timeout_ms = Some 2000; order = 0 }
          ) ips) in
    { servers; search = []; assume_offline_after_drops = None }

  module IntMap =
    Map.Make(struct
      type t = int
      let compare (a: int) (b: int) = Stdlib.compare a b
    end)

  let google_dns =
    let ips = [
      Ipaddr.of_string_exn "8.8.8.8", 53;
      Ipaddr.of_string_exn "8.8.4.4", 53;
    ] in
    `Upstream (config_of_ips ips)

  type priority = int

  let t = ref (IntMap.add 0 google_dns IntMap.empty)

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
    then
      Log.info (fun f ->
          f "Remove(%d): DNS configuration changed to: %s" priority
            (Config.to_string after))

  (* Watch for the /etc/resolv.file *)
  let resolv_conf = "/etc/resolv.conf"
  let () =
    match Files.watch_file resolv_conf (fun () ->
        Lwt.async (fun () ->
            Files.read_file resolv_conf
            >>= function
            | Error (`Msg m) ->
              Log.warn (fun f -> f "reading %s: %s" resolv_conf m);
              Lwt.return_unit
            | Ok txt ->
              begin match Dns_forward.Config.Unix.of_resolv_conf txt with
              | Error (`Msg m) ->
                Log.warn (fun f -> f "parsing %s: %s" resolv_conf m);
                Lwt.return_unit
              | Ok servers ->
                add ~priority:2 ~config:(`Upstream servers);
                Lwt.return_unit
              end
        )
      ) with
    | Error (`Msg "ENOENT") ->
      Log.info (fun f -> f "Not watching %s because it does not exist" resolv_conf)
    | Error (`Msg m) ->
      Log.info (fun f -> f "Cannot watch %s: %s" resolv_conf m)
    | Ok _watch ->
      Log.info (fun f -> f "Will watch %s for changes" resolv_conf)

end

let try_etc_hosts =
  let open Dns.Packet in
  function
  | { q_class = Q_IN; q_type = Q_A; q_name; _ } ->
    begin
      match List.fold_left (fun found (name, ip) ->
          match found, ip with
          | Some v4, _           -> Some v4
          | None,   Ipaddr.V4 v4 ->
            if Dns.Name.to_string q_name = name then Some v4 else None
          | None,   Ipaddr.V6 _  -> None
        ) None !(Hosts.etc_hosts)
      with
      | None -> None
      | Some v4 ->
        Some [ { name = q_name; cls = RR_IN;
                 flush = false; ttl = 0l; rdata = A v4 } ]
    end
  | { q_class = Q_IN; q_type = Q_AAAA; q_name; _ } ->
    begin
      match List.fold_left (fun found (name, ip) -> match found, ip with
        | Some v6, _           -> Some v6
        | None,   Ipaddr.V6 v6 ->
          if Dns.Name.to_string q_name = name then Some v6 else None
        | None,   Ipaddr.V4 _  -> None
        ) None !(Hosts.etc_hosts)
      with
      | None -> None
      | Some v6 ->
        Some [ { name = q_name; cls = RR_IN; flush = false; ttl = 0l;
                 rdata = AAAA v6 } ]
    end
  | _ -> None

let try_builtins builtin_names question =
  let open Dns.Packet in
  match question with
  | { q_class = Q_IN; q_type = (Q_A|Q_AAAA); q_name; _ } ->
    let bindings = List.filter (fun (name, _) -> name = q_name) builtin_names in
    if bindings = []
    then `Dont_know
    else begin
      let ipv4_rrs =
        List.fold_left (fun acc (_, ip) ->
          match ip with
          | Ipaddr.V4 ipv4 -> { name = q_name; cls = RR_IN; flush = false; ttl = 0l; rdata = A ipv4 } :: acc
          | _ -> acc
        ) [] bindings in
      let ipv6_rrs =
        List.fold_left (fun acc (_, ip) ->
          match ip with
          | Ipaddr.V6 ipv6 -> { name = q_name; cls = RR_IN; flush = false; ttl = 0l; rdata = AAAA ipv6 } :: acc
          | _ -> acc
        ) [] bindings in
      let rrs = if question.q_type = Q_A then ipv4_rrs else ipv6_rrs in
      if rrs = [] then begin
        Log.debug (fun f ->
          f "DNS: %s is a builtin but there are no resource records for %s"
            (Dns.Name.to_string q_name)
            (if question.q_type = Q_A then "IPv4" else "IPv6")
        );
        `Does_not_exist (* we've claimed the name but maybe don't have an AAAA record *)
      end else begin
        Log.debug (fun f ->
          f "DNS: %s is a builtin: %s" (Dns.Name.to_string q_name)
            (String.concat "; " (List.map (fun rr -> Dns.Packet.rr_to_string rr) rrs))
        );
        `Answers rrs
      end
    end
  | _ -> `Dont_know

module Make
    (Ip: Mirage_protocols.IPV4)
    (Udp:Mirage_protocols.UDPV4)
    (Tcp:Mirage_protocols.TCPV4)
    (Socket: Sig.SOCKETS)
    (D: Sig.DNS)
    (Time: Mirage_time.S)
    (Clock: Mirage_clock.MCLOCK)
    (Recorder: Sig.RECORDER) =
struct

  (* DNS uses slightly different protocols over TCP and UDP. We need
     both a UDP and TCP resolver configured to use the upstream
     servers. We will map UDP onto UDP and TCP onto TCP, leaving the
     client to handle the truncated bit and retransmissions. *)

  module Dns_tcp_client =
    Dns_forward.Rpc.Client.Persistent.Make(Socket.Stream.Tcp)
      (Dns_forward.Framing.Tcp(Socket.Stream.Tcp))(Time)

  module Dns_tcp_resolver =
    Dns_forward.Resolver.Make(Dns_tcp_client)(Time)(Clock)

  module Dns_udp_client =
    Dns_forward.Rpc.Client.Nonpersistent.Make(Socket.Datagram.Udp)
      (Dns_forward.Framing.Udp(Socket.Datagram.Udp))(Time)

  module Dns_udp_resolver =
    Dns_forward.Resolver.Make(Dns_udp_client)(Time)(Clock)

  (* We need to be able to parse the incoming framed TCP messages *)
  module Dns_tcp_framing = Dns_forward.Framing.Tcp(Tcp)

  type dns = {
    dns_tcp_resolver: Dns_tcp_resolver.t;
    dns_udp_resolver: Dns_udp_resolver.t;
  }

  type resolver =
    | Upstream of dns (* use upstream DNS servers *)
    | Host (* use the host resolver *)

  type t = {
    local_ip: Ipaddr.t;
    builtin_names: (Dns.Name.t * Ipaddr.t) list;
    resolver: resolver;
  }

  let recorder = ref None
  let set_recorder r = recorder := Some r

  let destroy = function
  | { resolver = Upstream { dns_tcp_resolver; dns_udp_resolver; _ }; _ } ->
    (* We need a source of randomness in this case *)
    let _ =
      match Utils.rtlGenRandom 1 with
      | None ->
        Log.warn (fun f -> f "No secure random number generator available")
      | Some _ ->
        Log.info (fun f -> f "Secure random number generator is available") in
    Dns_tcp_resolver.destroy dns_tcp_resolver
    >>= fun () ->
    Dns_udp_resolver.destroy dns_udp_resolver
  | { resolver = Host; _ } ->
    Log.info (fun f -> f "We do not need secure random numbers in Host mode");
    Lwt.return_unit

  let record_udp ~source_ip ~source_port ~dest_ip ~dest_port bufs =
    match !recorder with
    | Some recorder ->
      (* This is from mirage-tcpip-- ideally we would use a simpler
         packet creation fn *)
      let frame = Io_page.to_cstruct (Io_page.get 1) in
      let smac = "\000\000\000\000\000\000" in
      Ethernet_wire.set_ethernet_src smac 0 frame;
      Ethernet_wire.set_ethernet_ethertype frame 0x0800;
      let buf = Cstruct.shift frame Ethernet_wire.sizeof_ethernet in
      Ipv4_wire.set_ipv4_hlen_version buf ((4 lsl 4) + (5));
      Ipv4_wire.set_ipv4_tos buf 0;
      Ipv4_wire.set_ipv4_ttl buf 38;
      let proto = Ipv4_packet.Marshal.protocol_to_int `UDP in
      Ipv4_wire.set_ipv4_proto buf proto;
      Ipv4_wire.set_ipv4_src buf (Ipaddr.V4.to_int32 source_ip);
      Ipv4_wire.set_ipv4_dst buf (Ipaddr.V4.to_int32 dest_ip);
      let header_len =
        Ethernet_wire.sizeof_ethernet + Ipv4_wire.sizeof_ipv4
      in

      let frame = Cstruct.sub frame 0 (header_len + Udp_wire.sizeof_udp) in
      let udp_buf = Cstruct.shift frame header_len in
      Udp_wire.set_udp_source_port udp_buf source_port;
      Udp_wire.set_udp_dest_port udp_buf dest_port;
      Udp_wire.set_udp_length udp_buf (Udp_wire.sizeof_udp + Cstruct.lenv bufs);
      Udp_wire.set_udp_checksum udp_buf 0;
      (* Only for recording, no need to set a checksum. *)
      (* Ip.writev *)
      let bufs = frame :: bufs in
      let tlen = Cstruct.lenv bufs - Ethernet_wire.sizeof_ethernet in
      let dmac = String.make 6 '\000' in
      (* Ip.adjust_output_header *)
      Ethernet_wire.set_ethernet_dst dmac 0 frame;
      let buf =
        Cstruct.sub frame Ethernet_wire.sizeof_ethernet Ipv4_wire.sizeof_ipv4
      in
      (* Set the mutable values in the ipv4 header *)
      Ipv4_wire.set_ipv4_len buf tlen;
      Ipv4_wire.set_ipv4_id buf (Random.int 65535); (* TODO *)
      Ipv4_wire.set_ipv4_csum buf 0;
      (* Only for recording, no need to set a checksum *)
      Recorder.record recorder bufs
    | None ->
      () (* nowhere to log packet *)

  (* Generate a cryptograpically sure random number *)
  let gen_transaction_id bound =
    if bound <> 0x10000 then failwith "gen_transaction_id";
    match Utils.rtlGenRandom 2 with
    | Some bytes ->
      (int_of_char (Bytes.get bytes 0) lsl 8) lor (int_of_char (Bytes.get bytes 1))
    | None ->
      Random.int bound

  let create ~local_address ~builtin_names =
    let local_ip = local_address.Dns_forward.Config.Address.ip in
    Log.info (fun f ->
      let suffix = match builtin_names with
        | [] -> "no builtin DNS names; everything will be forwarded"
        | _ -> Printf.sprintf "builtin DNS names [ %s ]" (String.concat ", " @@ List.map (fun (name, ip) -> Dns.Name.to_string name ^ " -> " ^ (Ipaddr.to_string ip)) builtin_names) in
      f "DNS server configured with %s" suffix);
    function
    | `Upstream config ->
      let open Dns_forward.Config.Address in
      let nr_servers =
        let open Dns_forward.Config in
        Server.Set.cardinal config.servers in
      Log.info (fun f -> f "%d upstream DNS servers are configured" nr_servers);

      let message_cb ?(src = local_address) ?(dst = local_address) ~buf () =
        match src, dst with
        | { ip = Ipaddr.V4 source_ip; port = source_port },
          { ip = Ipaddr.V4 dest_ip; port = dest_port } ->
          record_udp ~source_ip ~source_port ~dest_ip ~dest_port [ buf ];
          Lwt.return_unit
        | _ ->
          (* We don't know how to marshal IPv6 yet *)
          Lwt.return_unit
      in
      Dns_udp_resolver.create ~gen_transaction_id ~message_cb config
      >>= fun dns_udp_resolver ->
      Dns_tcp_resolver.create ~gen_transaction_id ~message_cb config
      >>= fun dns_tcp_resolver ->
      Lwt.return { local_ip; builtin_names;
                   resolver = Upstream { dns_tcp_resolver; dns_udp_resolver } }
    | `Host ->
      Log.info (fun f -> f "Will use the host's DNS resolver");
      Lwt.return { local_ip; builtin_names; resolver = Host }

  let search f low high =
    if not(f low)
    then None (* none of the elements satisfy the predicate *)
    else
      let rec loop low high =
        if low = high
        then Some low
        else
          let mid = (low + high + 1) / 2 in
          (* since low <> high, mid <> low but it might be mid = high *)
          if f mid
          then loop mid high
          else
            if mid = high
            then Some low
            else loop low mid in
      loop low high

  let answer t is_tcp buf =
    let open Dns.Packet in
    let len = Cstruct.len buf in
    match Dns.Protocol.Server.parse (Cstruct.sub buf 0 len) with
    | None ->
      Lwt.return (Error (`Msg "failed to parse DNS packet"))
    | Some ({ questions = [ question ]; _ } as request) ->
      let reply ~tc answers =
        let id = request.id in
        let detail =
          { request.detail with Dns.Packet.qr = Dns.Packet.Response; ra = true; tc }
        in
        let questions = request.questions in
        let authorities = [] and additionals = [] in
        { Dns.Packet.id; detail; questions; answers; authorities; additionals }
      in
      let nxdomain =
        let id = request.id in
        let detail =
          { request.detail with Dns.Packet.qr = Dns.Packet.Response;
                                ra = true; rcode = Dns.Packet.NXDomain
          } in
        let questions = request.questions in
        let authorities = [] and additionals = [] and answers = []
        in
        { Dns.Packet.id; detail; questions; answers; authorities;
          additionals }
      in
      let marshal_reply answers =
        let buf = marshal @@ reply ~tc:false answers in
        if is_tcp
        then Some buf (* No need to truncate for TCP *)
        else begin
          (* If the packet is too big then set the TC bit and truncate by dropping answers *)
          let take n from =
            let rec loop n from acc = match n, from with
              | 0, _ -> acc
              | _, [] -> acc
              | n, x :: xs -> loop (n - 1) xs (x :: acc) in
            List.rev @@ loop n from [] in
          if Cstruct.len buf > max_udp_response then begin
            match search (fun num ->
              (* use only the first 'num' answers *)
              Cstruct.len (marshal @@ reply ~tc:true (take num answers)) <= max_udp_response
            ) 0 (List.length answers) with
            | None -> None
            | Some num -> Some (marshal @@ reply ~tc:true (take num answers))
          end
          else Some buf
        end in
      begin
        (* Consider the builtins (from the command-line) to have higher priority
           than the addresses in the /etc/hosts file. *)
        match try_builtins t.builtin_names question with
        | `Does_not_exist ->
          Lwt.return (Ok (Some (marshal nxdomain)))
        | `Answers answers ->
          Lwt.return (Ok (marshal_reply answers))
        | `Dont_know ->
          match try_etc_hosts question with
          | Some answers ->
            Lwt.return (Ok (marshal_reply answers))
          | None ->
            match is_tcp, t.resolver with
            | true, Upstream { dns_tcp_resolver; _ } ->
              begin
                Dns_tcp_resolver.answer buf dns_tcp_resolver
                >>= function
                | Error e -> Lwt.return (Error e)
                | Ok buf -> Lwt.return (Ok (Some buf))
              end
            | false, Upstream { dns_udp_resolver; _ } ->
              begin
                Dns_udp_resolver.answer buf dns_udp_resolver
                >>= function
                | Error e -> Lwt.return (Error e)
                | Ok buf ->
                  (* We need to parse and re-marshal so we can set the TC bit and truncate *)
                  begin match Dns.Protocol.Server.parse buf with
                  | None ->
                    Lwt.return (Error (`Msg "Failed to unmarshal DNS response from upstream"))
                  | Some { answers; _ } ->
                    Lwt.return (Ok (marshal_reply answers))
                  end
              end
            | _, Host ->
              D.resolve question
              >>= function
              | [] ->
                Lwt.return (Ok (Some (marshal nxdomain)))
              | answers ->
                Lwt.return (Ok (marshal_reply answers))
      end
    | _ ->
      Lwt.return (Error (`Msg "DNS packet had multiple questions"))

  let describe buf =
    let len = Cstruct.len buf in
    match Dns.Protocol.Server.parse (Cstruct.sub buf 0 len) with
    | None -> Printf.sprintf "Unparsable DNS packet length %d" len
    | Some request -> Dns.Packet.to_string request

  let handle_udp ~t ~udp ~src ~dst:_ ~src_port buf =
    answer t false buf
    >>= function
    | Error (`Msg m) ->
      Log.warn (fun f -> f "%s lookup failed: %s" (describe buf) m);
      Lwt.return (Ok ())
    | Ok None ->
      Log.err (fun f -> f "%s unable to marshal response" (describe buf));
      Lwt.return (Ok ())
    | Ok (Some buffer) ->
      Udp.write ~src_port:53 (* ~src:dst *) ~dst:src ~dst_port:src_port udp buffer

  let handle_tcp ~t =
    (* FIXME: need to record the upstream request *)
    let listeners _ =
      Log.debug (fun f -> f "DNS TCP handshake complete");
      let f flow =
        let packets = Dns_tcp_framing.connect flow in
        let rec loop () =
          Dns_tcp_framing.read packets >>= function
          | Error _    -> Lwt.return_unit
          | Ok request ->
            (* Perform queries in background threads *)
            let queries () =
              answer t true request >>= function
              | Error (`Msg m) ->
                Log.warn (fun f -> f "%s lookup failed: %s" (describe request) m);
                Lwt.return_unit
              | Ok None ->
                Log.err (fun f -> f "%s unable to marshal response to" (describe request));
                Lwt.return_unit
              | Ok (Some buffer) ->
                Dns_tcp_framing.write packets buffer >>= function
                | Error (`Msg m) ->
                  Log.warn (fun f ->
                      f "%s failed to write response: %s" (describe buffer) m);
                  Lwt.return_unit
                | Ok () ->
                  Lwt.return_unit
            in
            Lwt.async queries;
            loop ()
        in
        loop ()
      in
      Some f
    in
    Lwt.return listeners

end

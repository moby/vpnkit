let src =
  let src = Logs.Src.create "ppp" ~doc:"point-to-point network link" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Make(Input: Sig.VMNET) = struct

  type fd = Input.fd

  type stats = {
    mutable rx_bytes: int64;
    mutable rx_pkts: int32;
    mutable tx_bytes: int64;
    mutable tx_pkts: int32;
  }

  type t = {
    input: Input.t;
    stats: stats;
    valid_subnets: Ipaddr.V4.Prefix.t list;
    valid_sources: Ipaddr.V4.t list;
  }

  let connect ~valid_subnets ~valid_sources input =
    let stats = {
      rx_bytes = 0L; rx_pkts = 0l; tx_bytes = 0L; tx_pkts = 0l;
    } in
    Lwt.return (`Ok { input; stats; valid_subnets; valid_sources })

  let disconnect t = Input.disconnect t.input
  let after_disconnect t = Input.after_disconnect t.input

  let write t buf = Input.write t.input buf
  let writev t bufs = Input.writev t.input bufs

  let filter valid_subnets valid_sources next buf =
    match (Wire_structs.parse_ethernet_frame buf) with
    | Some (Some Wire_structs.IPv4, _, payload) ->
      let src = Ipaddr.V4.of_int32 @@ Wire_structs.Ipv4_wire.get_ipv4_src payload in
      let from_valid_networks = List.fold_left (fun acc network -> acc || (Ipaddr.V4.Prefix.mem src network)) false valid_subnets in
      let from_valid_sources = List.fold_left (fun acc valid -> acc || (Ipaddr.V4.compare src valid = 0)) false valid_sources in
      if from_valid_sources || from_valid_networks
      then next buf
      else begin
        let src = Ipaddr.V4.to_string src in
        let dst = Ipaddr.V4.to_string @@ Ipaddr.V4.of_int32 @@ Wire_structs.Ipv4_wire.get_ipv4_dst payload in
        let body = Cstruct.shift payload Wire_structs.Ipv4_wire.sizeof_ipv4 in
        begin match Wire_structs.Ipv4_wire.(int_to_protocol @@ get_ipv4_proto payload) with
          | Some `UDP ->
            let src_port = Wire_structs.get_udp_source_port body in
            let dst_port = Wire_structs.get_udp_dest_port body in
            Log.warn (fun f -> f "dropping unexpected UDP packet sent from %s:%d to %s:%d (valid subnets = %s; valid sources = %s)"
              src src_port dst dst_port
              (String.concat ", " (List.map Ipaddr.V4.Prefix.to_string valid_subnets))
              (String.concat ", " (List.map Ipaddr.V4.to_string valid_sources))
            )
          | Some `TCP ->
            let src_port = Wire_structs.Tcp_wire.get_tcp_src_port body in
            let dst_port = Wire_structs.Tcp_wire.get_tcp_dst_port body in
            Log.warn (fun f -> f "dropping unexpected TCP packet sent from %s:%d to %s:%d (valid subnets = %s; valid sources = %s)"
              src src_port dst dst_port
              (String.concat ", " (List.map Ipaddr.V4.Prefix.to_string valid_subnets))
              (String.concat ", " (List.map Ipaddr.V4.to_string valid_sources))
            )
          | _ ->
            Log.warn (fun f -> f "dropping unknown IP protocol %d sent from %s to %s (valid subnets = %s; valid sources = %s)"
              (Wire_structs.Ipv4_wire.get_ipv4_proto payload) src dst
              (String.concat ", " (List.map Ipaddr.V4.Prefix.to_string valid_subnets))
              (String.concat ", " (List.map Ipaddr.V4.to_string valid_sources))
            )
        end;
        Lwt.return ()
      end
    | _ -> next buf

  let listen t callback = Input.listen t.input @@ filter t.valid_subnets t.valid_sources callback
  let add_listener t callback = Input.add_listener t.input @@ filter t.valid_subnets t.valid_sources callback

  let mac t = Input.mac t.input

  type page_aligned_buffer = Io_page.t

  type buffer = Cstruct.t

  type error = [
    | `Unknown of string
    | `Unimplemented
    | `Disconnected
  ]

  type macaddr = Macaddr.t

  type 'a io = 'a Lwt.t

  type id = unit

  let get_stats_counters t = t.stats

  let reset_stats_counters t =
    t.stats.rx_bytes <- 0L;
    t.stats.tx_bytes <- 0L;
    t.stats.rx_pkts <- 0l;
    t.stats.tx_pkts <- 0l

  let of_fd ~client_macaddr_of_uuid:_ ~server_macaddr:_ ~mtu:_ =
    failwith "Filter.of_fd unimplemented"

  let get_client_uuid _ =
    failwith "Filter.get_client_uuid unimplemented"

  let get_client_macaddr _ =
    failwith "Filter.get_client_macaddr unimplemented"

  let start_capture _ ?size_limit:_ _ =
    failwith "Filter.start_capture unimplemented"

  let stop_capture _ =
    failwith "Filter.stop_capture unimplemented"
end

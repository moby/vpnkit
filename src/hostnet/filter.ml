open Lwt.Infix

let src =
  let src = Logs.Src.create "ppp" ~doc:"point-to-point network link" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Make(Input: Sig.VMNET) = struct

  type fd = Input.fd
  type error = [Mirage_net.Net.error | `Unknown of string]

  let pp_error ppf = function
  | #Mirage_net.Net.error as e -> Mirage_net.Net.pp_error ppf e
  | `Unknown s -> Fmt.pf ppf "unknown: %s" s

  let lift_error = function
  | Ok x    -> Ok x
  | Error (#Mirage_net.Net.error as e) -> Error e
  | Error e -> Fmt.kstr (fun s -> Error (`Unknown s)) "%a" Input.pp_error e

  type t = {
    input: Input.t;
    stats: Mirage_net.stats;
    valid_subnets: Ipaddr.V4.Prefix.t list;
    valid_sources: Ipaddr.V4.t list;
  }

  let connect ~valid_subnets ~valid_sources input =
    let stats = Mirage_net.Stats.create () in
    { input; stats; valid_subnets; valid_sources }

  let disconnect t = Input.disconnect t.input
  let after_disconnect t = Input.after_disconnect t.input

  let write t ~size fill = Input.write t.input ~size fill >|= lift_error

  let filter valid_subnets valid_sources next buf =
    match Ethernet.Packet.of_cstruct buf with
    | Ok (_header, payload) ->
      let src = Ipaddr.V4.of_int32 @@ Ipv4_wire.get_ipv4_src payload in
      let from_valid_networks =
        List.fold_left (fun acc network ->
            acc || (Ipaddr.V4.Prefix.mem src network)
          ) false valid_subnets
      in
      let from_valid_sources =
        List.fold_left (fun acc valid ->
            acc || (Ipaddr.V4.compare src valid = 0)
          ) false valid_sources
      in
      if from_valid_sources || from_valid_networks
      then next buf
      else begin
        let src = Ipaddr.V4.to_string src in
        let dst =
          Ipaddr.V4.to_string @@
          Ipaddr.V4.of_int32 @@
          Ipv4_wire.get_ipv4_dst payload
        in
        let body = Cstruct.shift payload Ipv4_wire.sizeof_ipv4 in
        begin match
          Ipv4_packet.Unmarshal.int_to_protocol
          @@ Ipv4_wire.get_ipv4_proto payload
        with
        | Some `UDP ->
          let src_port = Udp_wire.get_udp_source_port body in
          let dst_port = Udp_wire.get_udp_dest_port body in
          Log.warn (fun f ->
              f "dropping unexpected UDP packet sent from %s:%d to %s:%d \
                 (valid subnets = %s; valid sources = %s)"
                src src_port dst dst_port
                (String.concat ", "
                   (List.map Ipaddr.V4.Prefix.to_string valid_subnets))
                (String.concat ", "
                   (List.map Ipaddr.V4.to_string valid_sources))
            )
        | Some `TCP ->
          let src_port = Tcp.Tcp_wire.get_tcp_src_port body in
          let dst_port = Tcp.Tcp_wire.get_tcp_dst_port body in
          Log.warn (fun f ->
              f "dropping unexpected TCP packet sent from %s:%d to %s:%d \
                 (valid subnets = %s; valid sources = %s)"
                src src_port dst dst_port
                (String.concat ", "
                   (List.map Ipaddr.V4.Prefix.to_string valid_subnets))
                (String.concat ", "
                   (List.map Ipaddr.V4.to_string valid_sources))
            )
        | _ ->
          Log.warn (fun f ->
              f "dropping unknown IP protocol %d sent from %s to %s (valid \
                 subnets = %s; valid sources = %s)"
                (Ipv4_wire.get_ipv4_proto payload) src dst
                (String.concat ", "
                   (List.map Ipaddr.V4.Prefix.to_string valid_subnets))
                (String.concat ", "
                   (List.map Ipaddr.V4.to_string valid_sources))
            )
        end;
        Lwt.return ()
      end
    | _ -> next buf

  let listen t ~header_size callback =
    Input.listen t.input ~header_size (fun buf ->
      filter t.valid_subnets t.valid_sources callback buf
    ) >|= lift_error

  let add_listener t callback =
    Input.add_listener t.input @@ filter t.valid_subnets t.valid_sources callback

  let mac t = Input.mac t.input
  let mtu t = Input.mtu t.input
  let get_stats_counters t = t.stats
  let reset_stats_counters t = Mirage_net.Stats.reset t.stats

  let of_fd ~connect_client_fn:_ ~server_macaddr:_ ~mtu:_ =
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

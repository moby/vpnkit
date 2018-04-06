open Lwt.Infix
open Slirp_stack

let src =
  let src = Logs.Src.create "test" ~doc:"Test NTP" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let run ?(timeout=Duration.of_sec 60) t =
  let timeout =
    Host.Time.sleep_ns timeout >>= fun () ->
    Lwt.fail_with "timeout"
  in
  Host.Main.run @@ Lwt.pick [ timeout; t ]

let err_udp e = Fmt.kstrf failwith "%a" Client.UDPV4.pp_error e

(* Send an NTP request *)
let test_ntp() =
  let t =
    with_stack ~pcap:"test_ntp.pcap"  (fun _ stack ->
      let virtual_port = 1024 in

      let packet_t, packet_u = Lwt.task () in

      Client.listen_udpv4 stack.t ~port:virtual_port (fun ~src:_ ~dst:_ ~src_port:_ buffer ->
        match Ntp_wire.pkt_of_buf buffer with
        | None ->
          Log.err (fun f -> f "failed to parse NTP response: %a" Cstruct.hexdump_pp buffer);
          Lwt.return_unit
        | Some pkt ->
          Lwt.wakeup_later packet_u pkt;
        Lwt.return_unit
      );

      let request =
        let open Ntp_wire in {
          leap = NoWarning;
          version = 4;
          mode = Client;
          stratum = Secondary 1;
          poll = 0;
          precision = 0;
          root_delay = { seconds = 0; fraction = 0 };
          root_dispersion = { seconds = 0; fraction = 0 };
          refid = 0l;
          reference_ts = { timestamp = 1L };
          origin_ts = { timestamp = 2L };
          recv_ts = { timestamp = 3L };
          trans_ts = { timestamp = 4L };
        } in
        let buffer = Ntp_wire.buf_of_pkt request in
        let udpv4 = Client.udpv4 stack.t in
        let rec loop remaining =
          if remaining = 0 then
            failwith "Timed-out before UDP response arrived";
          Log.debug (fun f -> f "Sending %d -> 123" virtual_port);
          Client.UDPV4.write
            ~src_port:virtual_port
            ~dst:primary_dns_ip
            ~dst_port:123 udpv4 buffer
          >>= function
          | Error e -> err_udp e
          | Ok ()   ->
            Lwt.pick [
              (Host.Time.sleep_ns (Duration.of_sec 1) >|= fun () -> `Timeout);
              (packet_t >|= fun p -> `Ok p)
            ]
            >>= function
            | `Timeout ->
              loop (remaining - 1)
            | `Ok reply ->
              let open Ntp_wire in
              assert (reply.leap = NoWarning);
              assert (reply.version = 4);
              assert (reply.mode = Server);
              assert (reply.stratum = Primary);
              assert (reply.refid > 0l);
              assert (reply.reference_ts.timestamp <> 1L);
              assert (reply.origin_ts.timestamp = 4L); (* original trans_ts *)
              assert (reply.recv_ts.timestamp <> 3L);
              assert (reply.trans_ts.timestamp <> 4L);
              Lwt.return_unit
          in
          loop 5
        )
  in
  run t

let tests = [
  "NTP: got reply", [ "", `Quick, test_ntp ];
]

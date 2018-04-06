let src =
  let src = Logs.Src.create "ntp" ~doc:"Simple NTP implementation" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Make
    (Ip: Mirage_protocols_lwt.IPV4)
    (Udp:Mirage_protocols_lwt.UDPV4)
    (Clock: Mirage_clock_lwt.MCLOCK) =
struct


  let reply request = request

  let handle_udp ~udp ~src ~dst:_ ~src_port buf =
    match Ntp_wire.pkt_of_buf buf with
    | None ->
      Log.warn (fun f -> f "Failed to parse NTP packet: %a" Cstruct.hexdump_pp buf);
      Lwt.return (Ok ())
    | Some request ->
      let buf' = Ntp_wire.buf_of_pkt @@ reply request in
      Udp.write ~src_port:123 ~dst:src ~dst_port:src_port udp buf'

end

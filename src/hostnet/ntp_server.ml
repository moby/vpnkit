let src =
  let src = Logs.Src.create "ntp" ~doc:"Simple NTP implementation" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Make
    (Ip: Mirage_protocols_lwt.IPV4)
    (Udp:Mirage_protocols_lwt.UDPV4)
    (Clock: Mirage_clock_lwt.PCLOCK) =
struct

  (* From RFC2030 LOCL is an
     > uncalibrated local clock used as a primary reference for
     > a subnet without external means of synchronization *)
  let local_reference_identifier =
    let buf = Cstruct.create 4 in
    Cstruct.blit_from_string "LOCL" 0 buf 0 4;
    Cstruct.BE.get_uint32 buf 0

  (* Convert a Mirage PCLOCK (days, picoseconds) into an NTP timestamp *)
  let timestamp (days, picoseconds) =
    (* Posix time starts at   1970-01-01 00:00:00 UTC
       but NTP time starts at 1900-01-01 00:00:00 UTC.
       There were 17 leap years between 1900 and 1970.
       Leap seconds started from 1972 so are irrelevant here.
    *)
    let days' = days + 70 * 365 + 17 in
    let seconds = days' * 86400 + Int64.(to_int @@ div picoseconds 1_000_000_000_000L) in
    let microseconds = Int64.(rem (div picoseconds 1_000_000L) 1_000_000L) in
    let fraction = Int64.(div (shift_left microseconds 32) 1_000_000L) in
    { Ntp_wire.timestamp = Int64.(logor (shift_left (of_int seconds) 32) fraction) }

  let reply request timestamp =
    let open Ntp_wire in
    {
      leap = NoWarning;
      version = request.version;
      mode = (if request.mode = Client then Server else SymP);
      stratum = Primary;
      poll = request.poll;
      precision = -20; (* 2 ^ -20 seconds i.e. about a microsecond *)
      root_delay = { seconds = 0; fraction = 0 };
      root_dispersion = { seconds = 0; fraction = 0 };
      refid = local_reference_identifier;
      reference_ts = timestamp;
      origin_ts = request.trans_ts;
      recv_ts = timestamp;
      trans_ts = timestamp;
    }

  let handle_udp ~clock ~udp ~src ~dst:_ ~src_port buf =
    match Ntp_wire.pkt_of_buf buf with
    | None ->
      Log.warn (fun f -> f "Failed to parse NTP packet: %a" Cstruct.hexdump_pp buf);
      Lwt.return (Ok ())
    | Some request ->
      let now = Clock.now_d_ps clock in
      let timestamp = timestamp now in
      let buf' = Ntp_wire.buf_of_pkt @@ reply request timestamp in
      Udp.write ~src_port:123 ~dst:src ~dst_port:src_port udp buf'

end

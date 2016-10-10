let src =
  let src = Logs.Src.create "capture" ~doc:"capture network traffic" in
  Logs.Src.set_level src (Some Logs.Debug);
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

  type packet = {
    len: int;
    time: float;
    bufs: Cstruct.t list;
  }

  type rule = {
    predicate: Match.t;
    limit: int;
    packets: packet Queue.t;
    mutable nr_bytes: int;
  }

  let push rule bufs =
    let len = List.fold_left (+) 0 (List.map Cstruct.len bufs) in
    let time = Unix.gettimeofday () in
    let packet = { len; time; bufs } in
    Queue.push packet rule.packets;
    rule.nr_bytes <- rule.nr_bytes + len;
    while rule.nr_bytes > rule.limit do
      let to_drop = Queue.pop rule.packets in
      rule.nr_bytes <- rule.nr_bytes - to_drop.len;
    done

  let pcap rule =
    let stat () =
      Vfs.ok { Vfs.perm = `Normal; length = Int64.of_int rule.nr_bytes } in
    let remove () = Vfs.error "remove()" in
    let truncate _size = Vfs.error "truncate" in
    let chmod _perm = Vfs.error "chmod" in

    let file_header_buf = Cstruct.create Pcap.LE.sizeof_pcap_header in
    let open Pcap.LE in
    set_pcap_header_magic_number file_header_buf Pcap.magic_number;
    set_pcap_header_version_major file_header_buf Pcap.major_version;
    set_pcap_header_version_minor file_header_buf Pcap.minor_version;
    set_pcap_header_thiszone file_header_buf 0l;
    set_pcap_header_sigfigs file_header_buf 4l;
    set_pcap_header_snaplen file_header_buf 1500l;
    set_pcap_header_network file_header_buf (Pcap.Network.to_int32 Pcap.Network.Ethernet);

    let frame_header_buf = Cstruct.create Pcap.sizeof_pcap_packet in
    let frame_header p =
      let secs = Int32.of_float p.time in
      let usecs = Int32.of_float (1e6 *. (p.time -. (floor p.time))) in
      let open Pcap.LE in
      set_pcap_packet_ts_sec frame_header_buf secs;
      set_pcap_packet_ts_usec frame_header_buf usecs;
      set_pcap_packet_incl_len frame_header_buf @@ Int32.of_int p.len;
      set_pcap_packet_orig_len frame_header_buf @@ Int32.of_int p.len;
      frame_header_buf in

    let open_ () =
      (* Capture a copy of the packet queue and synthesize a (lazily-marshalled)
         view of the data *)
      let length, fragments =
        let hdr = 0, fun () -> file_header_buf in
        let offset = Cstruct.len file_header_buf in
        let _, packets = Queue.fold (fun (offset, acc) pkt ->
          let packet_hdr = offset, fun () -> frame_header pkt in
          let offset = offset + (Cstruct.len frame_header_buf) in
          (* assemble packet bodies reversed, in a reversed list of packets *)
          let offset, packet_bodies = List.fold_left (fun (offset, acc) buf ->
            let this = offset, fun () -> buf in
            offset + (Cstruct.len buf), this :: acc
          ) (offset, []) pkt.bufs in
          offset, packet_bodies @ [ packet_hdr ] @ acc
        ) (offset, []) rule.packets in
        let length = match packets with
          | [] -> Cstruct.len file_header_buf
          | (x, buf_fn) :: _ -> x + (Cstruct.len (buf_fn ())) in
        length, hdr :: (List.rev packets) in
      let read ~offset ~count =
        (* Check if we try to read beyond the end of the file *)
        let offset = Int64.to_int offset in
        let dst_len = min count (length - offset) in
        let dst = Cstruct.create dst_len in

        List.iter (fun (offset', src_fn) ->
          let src = src_fn () in
          let count' = Cstruct.len src in
          (* Consider 4 cases of this packet relative to the requested region
            - this packet is completely before
            - this packet is completely after
            - this packet partially overlaps from the left
            - this packet partially overlaps with the right *)
          let before = offset' + count' < offset  (* completely before *)
          and after  = (offset + count) < offset' (* completely after  *) in
          let srcoff, dstoff, len =
            if before || after
            then 0, 0, 0
            else
              if offset' > offset then begin
                let dstoff = offset' - offset in
                let srcoff = 0 in
                let len = min count' (count - dstoff) in
                srcoff, dstoff, len
              end else begin
                let dstoff = 0 in
                let srcoff = offset - offset' in
                let len = min (count' - srcoff) count in
                srcoff, dstoff, len
              end in
          Cstruct.blit src srcoff dst dstoff len
        ) fragments;
        Vfs.ok dst in
      let write ~offset:_ _ =
        Vfs.error "write" in
      Vfs.ok (Vfs.File.create_fd ~read ~write) in
    Vfs.File.create ~stat ~open_ ~remove ~truncate ~chmod

  type t = {
    input: Input.t;
    rules: (string, rule) Hashtbl.t;
    stats: stats;
  }

  let connect input =
    let rules = Hashtbl.create 7 in
    let stats = {
      rx_bytes = 0L; rx_pkts = 0l; tx_bytes = 0L; tx_pkts = 0l;
    } in
    Lwt.return (`Ok { input; rules; stats })

  let add_match ~t ~name ~limit predicate =
    let packets = Queue.create () in
    let nr_bytes = 0 in
    let rule = { predicate; limit; packets; nr_bytes } in
    Hashtbl.replace t.rules name rule

  let filesystem t =
    Vfs.Dir.of_list
      (fun () ->
        Vfs.ok (
          Hashtbl.fold
            (fun name rule acc -> Vfs.Inode.file name (pcap rule) :: acc)
          t.rules []
        )
      )

  let disconnect t = Input.disconnect t.input
  let after_disconnect t = Input.after_disconnect t.input

  let record t bufs =
    Hashtbl.iter
      (fun name rule ->
        if Match.bufs rule.predicate bufs then push rule bufs
      ) t.rules

  let write t buf =
    record t [ buf ];
    Input.write t.input buf
  let writev t bufs =
    record t bufs;
    Input.writev t.input bufs

  let listen t callback =
    Input.listen t.input (fun buf -> record t [ buf ]; callback buf)

  let add_listener t callback = Input.add_listener t.input callback

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

  let of_fd ~client_macaddr:_ ~server_macaddr:_ =
    failwith "Capture.of_fd unimplemented"

  let start_capture _ ?size_limit:_ _ =
    failwith "Capture.start_capture unimplemented"

  let stop_capture _ =
    failwith "Capture.stop_capture unimplemented"
end

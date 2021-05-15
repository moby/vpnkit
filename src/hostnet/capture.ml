open Lwt.Infix

let src =
  let src = Logs.Src.create "capture" ~doc:"capture network traffic" in
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
  | Error e -> Fmt.kstrf (fun s -> Error (`Unknown s)) "%a" Input.pp_error e

  type packet = {
    id: int; (* unique id *)
    len: int;
    orig_len: int;
    time: float;
    bufs: Cstruct.t list;
  }

  type rule = {
    predicate: Frame.t -> bool;
    snaplen: int;
    limit: int;
    packets: packet Queue.t;
    packets_c: unit Lwt_condition.t;
    mutable nr_bytes: int;
  }

  let initial_packet_id = 0
  let next_packet_id = ref initial_packet_id

  let push rule bufs =
    let orig_len = List.fold_left (+) 0 (List.map Cstruct.len bufs) in
    let bufs =
      if Cstructs.len bufs > rule.snaplen
      then Cstructs.sub bufs 0 rule.snaplen
      else bufs
    in
    let len = List.fold_left (+) 0 (List.map Cstruct.len bufs) in
    let time = Unix.gettimeofday () in
    let id = !next_packet_id in
    incr next_packet_id;
    let packet = { id; len; orig_len; time; bufs } in
    Queue.push packet rule.packets;
    Lwt_condition.broadcast rule.packets_c ();
    rule.nr_bytes <- rule.nr_bytes + len;
    while rule.nr_bytes > rule.limit do
      let to_drop = Queue.pop rule.packets in
      rule.nr_bytes <- rule.nr_bytes - to_drop.len;
    done

  let write_file_header file_header_buf rule =
    let open Pcap.LE in
    set_pcap_header_magic_number file_header_buf Pcap.magic_number;
    set_pcap_header_version_major file_header_buf Pcap.major_version;
    set_pcap_header_version_minor file_header_buf Pcap.minor_version;
    set_pcap_header_thiszone file_header_buf 0l;
    set_pcap_header_sigfigs file_header_buf 4l;
    set_pcap_header_snaplen file_header_buf (Int32.of_int rule.snaplen);
    set_pcap_header_network file_header_buf
      (Pcap.Network.to_int32 Pcap.Network.Ethernet)

  let frame_header frame_header_buf p =
    let secs = Int32.of_float p.time in
    let usecs = Int32.of_float (1e6 *. (p.time -. (floor p.time))) in
    let open Pcap.LE in
    set_pcap_packet_ts_sec frame_header_buf secs;
    set_pcap_packet_ts_usec frame_header_buf usecs;
    set_pcap_packet_incl_len frame_header_buf @@ Int32.of_int p.len;
    set_pcap_packet_orig_len frame_header_buf @@ Int32.of_int p.orig_len;
    frame_header_buf

  let to_pcap rule =
    let file_header_buf = Cstruct.create Pcap.LE.sizeof_pcap_header in
    write_file_header file_header_buf rule;
    let header = Lwt_stream.of_list [ [ file_header_buf ] ] in
    let last_seen_packet_id = ref (initial_packet_id - 1) in
    let body () =
      let rec wait () =
        let new_packets =
          Queue.fold
            (fun acc p ->
              if p.id > !last_seen_packet_id
              then p :: acc
              else acc
            ) [] rule.packets |> List.rev in
        if new_packets = [] then begin
          Lwt_condition.wait rule.packets_c
          >>= fun () ->
          wait ()
        end else Lwt.return new_packets in
      wait ()
      >>= fun new_packets ->
      (* We could note the number of dropped packets here *)
      last_seen_packet_id := List.fold_left max !last_seen_packet_id (List.map (fun p -> p.id) new_packets);
      let marshalled_packets = List.map (fun p ->
          let header = frame_header (Cstruct.create Pcap.sizeof_pcap_packet) p in
          header :: p.bufs
      ) new_packets in
      Lwt.return (Some (List.concat marshalled_packets)) in
    Lwt_stream.(append header (from body))

  let pcap rule =
    let stat () =
      Vfs.ok { Vfs.perm = `Normal; length = Int64.of_int rule.nr_bytes } in
    let remove () = Vfs.error "remove()" in
    let truncate _size = Vfs.error "truncate" in
    let chmod _perm = Vfs.error "chmod" in

    let file_header_buf = Cstruct.create Pcap.LE.sizeof_pcap_header in
    write_file_header file_header_buf rule;

    let frame_header_buf = Cstruct.create Pcap.sizeof_pcap_packet in

    let open_ () =
      (* Capture a copy of the packet queue and synthesize a (lazily-marshalled)
         view of the data *)
      let length, fragments =
        let hdr = 0, fun () -> file_header_buf in
        let offset = Cstruct.len file_header_buf in
        let _, packets = Queue.fold (fun (offset, acc) pkt ->
            let packet_hdr = offset, fun () -> frame_header frame_header_buf pkt in
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
    stats: Mirage_net.stats;
  }

  let add_match ~t ~name ~limit ~snaplen ~predicate =
    let packets = Queue.create () in
    let packets_c = Lwt_condition.create () in
    let nr_bytes = 0 in
    let rule = { predicate; limit; snaplen; packets; packets_c; nr_bytes } in
    Hashtbl.replace t.rules name rule;
    rule

  let bad_pcap = "bad.pcap"

  let connect input =
    let rules = Hashtbl.create 7 in
    let stats = Mirage_net.Stats.create () in
    let t = { input; rules; stats } in
    (* Add a special capture rule for packets for which there is an error
       processing the packet captures. Ideally there should be no matches! *)
    let (_: rule) = add_match ~t ~name:bad_pcap ~limit:1048576 ~snaplen:1500
      ~predicate:(fun _ -> false) in
    t

  let filesystem t =
    Vfs.Dir.of_list (fun () ->
        Vfs.ok (
          Hashtbl.fold
            (fun name rule acc -> Vfs.Inode.file name (pcap rule) :: acc)
            t.rules []
        )
      )

  let disconnect t = Input.disconnect t.input
  let after_disconnect t = Input.after_disconnect t.input

  let record t bufs =
    try
      Hashtbl.iter (fun _ rule ->
          match Frame.parse bufs with
          | Ok f -> if rule.predicate f then push rule bufs
          | Error (`Msg m) -> failwith m
        ) t.rules
    with e ->
      Log.err (fun f -> f "caught %s matching packet" (Printexc.to_string e));
      let rule = Hashtbl.find t.rules bad_pcap in
      push rule bufs

  let write t ~size fill =
    Input.write t.input ~size (fun buf ->
      let n = fill buf in
      record t [ Cstruct.sub buf 0 n ];
      n
    ) >|= lift_error

  let listen t ~header_size callback =
    Input.listen t.input ~header_size (fun buf ->
        record t [ buf ];
        callback buf
    ) >|= lift_error

  let add_listener t callback = Input.add_listener t.input callback

  let mac t = Input.mac t.input

  let mtu t = Input.mtu t.input

  let get_stats_counters t = t.stats

  let reset_stats_counters t =
    t.stats.rx_bytes <- 0L;
    t.stats.tx_bytes <- 0L;
    t.stats.rx_pkts <- 0l;
    t.stats.tx_pkts <- 0l

  let of_fd ~connect_client_fn:_ ~server_macaddr:_ ~mtu:_ =
    failwith "Capture.of_fd unimplemented"

  let start_capture _ ?size_limit:_ _ =
    failwith "Capture.start_capture unimplemented"

  let stop_capture _ =
    failwith "Capture.stop_capture unimplemented"

  let get_client_uuid _ =
    failwith "Capture.get_client_uuid unimplemented"

  let get_client_macaddr _ =
    failwith "Capture.get_client_macaddr unimplemented"
end

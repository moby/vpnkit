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
    bufs: Cstruct.t list;
  }

  type t = {
    input: Input.t;
    limit: int;
    packets: packet Queue.t;
    mutable nr_bytes: int;
    stats: stats;
  }

  let connect ~limit input =
    let packets = Queue.create () in
    let nr_bytes = 0 in
    let stats = {
      rx_bytes = 0L; rx_pkts = 0l; tx_bytes = 0L; tx_pkts = 0l;
    } in
    Lwt.return (`Ok { input; limit; packets; nr_bytes; stats })

  let disconnect t = Input.disconnect t.input
  let after_disconnect t = Input.after_disconnect t.input

  let record t bufs =
    let len = List.fold_left (+) 0 (List.map Cstruct.len bufs) in
    let packet = { len; bufs } in
    Queue.push packet t.packets;
    t.nr_bytes <- t.nr_bytes + len;
    while t.nr_bytes > t.limit do
      let to_drop = Queue.pop t.packets in
      t.nr_bytes <- t.nr_bytes - to_drop.len;
    done

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

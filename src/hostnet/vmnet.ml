module Lwt_result = Hostnet_lwt_result (* remove when new Lwt is released *)

open Lwt
open Sexplib.Std

let src =
  let src = Logs.Src.create "vmnet" ~doc:"vmnet" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let log_exception_continue description f =
  Lwt.catch
    (fun () -> f ())
    (fun e ->
       Log.err (fun f -> f "%s: caught %s" description (Printexc.to_string e));
       Lwt.return ()
    )

let ethernet_header_length = 14 (* no VLAN *)

module Init = struct

  type t = {
    magic: string;
    version: int32;
    commit: string;
  }

  let to_string t =
    Printf.sprintf "{ magic = %s; version = %ld; commit = %s }" t.magic t.version t.commit

  let sizeof = 5 + 4 + 40

  let default = {
    magic = "VMN3T";
    version = 1l;
    commit = "0123456789012345678901234567890123456789";
  }

  let marshal t rest =
    Cstruct.blit_from_string t.magic 0 rest 0 5;
    Cstruct.LE.set_uint32 rest 5 t.version;
    Cstruct.blit_from_string t.commit 0 rest 9 40;
    Cstruct.shift rest sizeof

  let unmarshal rest =
    let magic = Cstruct.(to_string @@ sub rest 0 5) in
    let version = Cstruct.LE.get_uint32 rest 5 in
    let commit = Cstruct.(to_string @@ sub rest 9 40) in
    let rest = Cstruct.shift rest sizeof in
    Result.Ok ({ magic; version; commit }, rest)
end

module Command = struct

  type t =
    | Ethernet of Uuidm.t (* 36 bytes *)
    | Bind_ipv4 of Ipaddr.V4.t * int * bool

  let to_string = function
    | Ethernet x -> "Ethernet " ^ (Uuidm.to_string x)
    | Bind_ipv4 (ip, port, tcp) -> "Bind_ipv4 " ^ (Ipaddr.V4.to_string ip) ^ " " ^ (string_of_int port) ^ " " ^ (string_of_bool tcp)

  let sizeof = 1 + 36

  let marshal t rest = match t with
    | Ethernet uuid ->
      Cstruct.set_uint8 rest 0 1;
      let rest = Cstruct.shift rest 1 in
      let uuid_str = Uuidm.to_string uuid in
      Cstruct.blit_from_string uuid_str 0 rest 0 (String.length uuid_str);
      Cstruct.shift rest (String.length uuid_str)
    | Bind_ipv4 (ip, port, stream) ->
      Cstruct.set_uint8 rest 0 6;
      let rest = Cstruct.shift rest 1 in
      Cstruct.LE.set_uint32 rest 0 (Ipaddr.V4.to_int32 ip);
      let rest = Cstruct.shift rest 4 in
      Cstruct.LE.set_uint16 rest 0 port;
      let rest = Cstruct.shift rest 2 in
      Cstruct.set_uint8 rest 0 (if stream then 0 else 1);
      Cstruct.shift rest 1

  let unmarshal rest =
    match Cstruct.get_uint8 rest 0 with
    | 1 ->
      let uuid_str = Cstruct.(to_string (sub rest 1 36)) in
      let rest = Cstruct.shift rest 37 in
      let result = match (Uuidm.of_string uuid_str) with
          | Some uuid -> begin
            Result.Ok (Ethernet uuid, rest)
          end
          | None -> Result.Error (`Msg (Printf.sprintf "Invalid UUID: %s" uuid_str))
      in 
      result
    | n -> Result.Error (`Msg (Printf.sprintf "Unknown command: %d" n))

end

module Vif = struct

  type t = {
    mtu: int;
    max_packet_size: int;
    client_macaddr: Macaddr.t;
  }

  let to_string t = Printf.sprintf "{ mtu = %d; max_packet_size = %d; client_macaddr = %s }" t.mtu t.max_packet_size (Macaddr.to_string t.client_macaddr)

  let create client_macaddr mtu () =
    let max_packet_size = mtu + 50 in
    { mtu; max_packet_size; client_macaddr }

  let sizeof = 2 + 2 + 6

  let marshal t rest =
    Cstruct.LE.set_uint16 rest 0 t.mtu;
    Cstruct.LE.set_uint16 rest 2 t.max_packet_size;
    Cstruct.blit_from_bytes (Macaddr.to_bytes t.client_macaddr) 0 rest 4 6; 
    Cstruct.shift rest sizeof

  let unmarshal rest =
    let mtu = Cstruct.LE.get_uint16 rest 0 in
    let max_packet_size = Cstruct.LE.get_uint16 rest 2 in
    let mac = Cstruct.(to_string @@ sub rest 4 6) in
    try
      let client_macaddr = Macaddr.of_bytes_exn mac in
      Result.Ok ({ mtu; max_packet_size; client_macaddr }, Cstruct.shift rest sizeof)
    with _ ->
      Result.Error (`Msg (Printf.sprintf "Failed to parse MAC: [%s]" mac))

end

module Packet = struct
  let sizeof = 2

  let marshal t rest =
    Cstruct.LE.set_uint16 rest 0 t

  let unmarshal rest =
    let t = Cstruct.LE.get_uint16 rest 0 in
    Result.Ok (t, Cstruct.shift rest sizeof)
end

module Make(C: Sig.CONN) = struct

module Channel = Channel.Make(C)

type stats = {
  mutable rx_bytes: int64;
  mutable rx_pkts: int32;
  mutable tx_bytes: int64;
  mutable tx_pkts: int32;
}

type t = {
  mutable fd: Channel.t option;
  stats: stats;
  client_uuid: Uuidm.t;
  client_macaddr: Macaddr.t;
  server_macaddr: Macaddr.t;
  mtu: int;
  mutable write_header: Cstruct.t;
  write_m: Lwt_mutex.t;
  mutable pcap: Unix.file_descr option;
  mutable pcap_size_limit: int64 option;
  pcap_m: Lwt_mutex.t;
  mutable listeners: (Cstruct.t -> unit Lwt.t) list;
  mutable listening: bool;
  after_disconnect: unit Lwt.t;
  after_disconnect_u: unit Lwt.u;
}


let error_of_failure f = Lwt.catch f (fun e -> Lwt_result.fail (`Msg (Printexc.to_string e)))

let get_fd t = match t.fd with
  | Some fd -> fd
  | None -> failwith "Vmnet connection is disconnected"

let get_client_uuid t =
  t.client_uuid

let get_client_macaddr t =
  t.client_macaddr

let server_negotiate ~fd ~client_macaddr_of_uuid ~mtu =
  error_of_failure
    (fun () ->
      Channel.read_exactly ~len:Init.sizeof fd
      >>= fun bufs ->
      let buf = Cstruct.concat bufs in
      let open Lwt_result.Infix in
      Lwt.return (Init.unmarshal buf)
      >>= fun (init, _) ->
      Log.info (fun f -> f "PPP.negotiate: received %s" (Init.to_string init));
      let (_: Cstruct.t) = Init.marshal Init.default buf in
      let open Lwt.Infix in
      Channel.write_buffer fd buf;
      Channel.flush fd
      >>= fun () ->
      Channel.read_exactly ~len:Command.sizeof fd
      >>= fun bufs ->
      let buf = Cstruct.concat bufs in
      let open Lwt_result.Infix in
      Lwt.return (Command.unmarshal buf)
      >>= fun (command, _) ->
      Log.info (fun f -> f "PPP.negotiate: received %s" (Command.to_string command));
      match command with
      | Ethernet uuid -> begin
          let open Lwt.Infix in
          client_macaddr_of_uuid uuid
          >>= fun client_macaddr -> 
          let vif = Vif.create client_macaddr mtu () in
          let buf = Cstruct.create Vif.sizeof in
          let (_: Cstruct.t) = Vif.marshal vif buf in
          let open Lwt.Infix in
          Log.info (fun f -> f "PPP.negotiate: sending %s" (Vif.to_string vif));
          Channel.write_buffer fd buf;
          Channel.flush fd
          >>= fun () ->
          Lwt_result.return (uuid, client_macaddr)
        end
      | Bind_ipv4 _ -> (raise (Failure "PPP.negotiate: unsupported command Bind_ipv4"))
    )

let client_negotiate ~uuid ~fd =
  error_of_failure
    (fun () ->
      let open Lwt.Infix in
      let buf = Cstruct.create Init.sizeof in
      let (_: Cstruct.t) = Init.marshal Init.default buf in
      Channel.write_buffer fd buf;
      Channel.flush fd
      >>= fun () ->
      Channel.read_exactly ~len:Init.sizeof fd
      >>= fun bufs ->
      let buf = Cstruct.concat bufs in
      let open Lwt_result.Infix in
      Lwt.return (Init.unmarshal buf)
      >>= fun (init, _) ->
      Log.info (fun f -> f "Client.negotiate: received %s" (Init.to_string init));
      let buf = Cstruct.create Command.sizeof in
      let (_: Cstruct.t) = Command.marshal (Command.Ethernet uuid) buf in
      let open Lwt.Infix in
      Channel.write_buffer fd buf;
      Channel.flush fd
      >>= fun () ->
      Channel.read_exactly ~len:Vif.sizeof fd
      >>= fun bufs ->
      let buf = Cstruct.concat bufs in
      let open Lwt_result.Infix in
      Lwt.return (Vif.unmarshal buf)
      >>= fun (vif, _) ->
      Log.debug (fun f -> f "Client.negotiate: vif %s" (Vif.to_string vif));
      Lwt_result.return (vif)
    )

(* Use blocking I/O here so we can avoid Using Lwt_unix or Uwt. Ideally we
   would use a FLOW handle referencing a file/stream. *)
let really_write fd str =
  let rec loop ofs =
    if ofs = (String.length str)
    then ()
    else
      let n = Unix.write fd str ofs (String.length str - ofs) in
      loop (ofs + n) in
  loop 0

let start_capture t ?size_limit filename =
  Lwt_mutex.with_lock t.pcap_m
    (fun () ->
      ( match t.pcap with
        | Some fd ->
          Unix.close fd;
          Lwt.return ()
        | None ->
          Lwt.return ()
      ) >>= fun () ->
      let fd = Unix.openfile filename [ Unix.O_WRONLY; Unix.O_TRUNC; Unix.O_CREAT ] 0o0644 in
      let buf = Cstruct.create Pcap.LE.sizeof_pcap_header in
      let open Pcap.LE in
      set_pcap_header_magic_number buf Pcap.magic_number;
      set_pcap_header_version_major buf Pcap.major_version;
      set_pcap_header_version_minor buf Pcap.minor_version;
      set_pcap_header_thiszone buf 0l;
      set_pcap_header_sigfigs buf 4l;
      set_pcap_header_snaplen buf 1500l;
      set_pcap_header_network buf (Pcap.Network.to_int32 Pcap.Network.Ethernet);
      really_write fd (Cstruct.to_string buf);
      t.pcap <- Some fd;
      t.pcap_size_limit <- size_limit;
      Lwt.return ()
    )

let stop_capture_already_locked t = match t.pcap with
  | None -> Lwt.return ()
  | Some fd ->
    Unix.close fd;
    t.pcap <- None;
    t.pcap_size_limit <- None;
    Lwt.return ()

let stop_capture t =
  Lwt_mutex.with_lock t.pcap_m
    (fun () ->
      stop_capture_already_locked t
    )

let make ~client_macaddr ~server_macaddr ~mtu ~client_uuid fd =
  let fd = Some fd in
  let stats = { rx_bytes = 0L; rx_pkts = 0l; tx_bytes = 0L; tx_pkts = 0l } in
  let write_header = Cstruct.create (1024 * Packet.sizeof) in
  let write_m = Lwt_mutex.create () in
  let pcap = None in
  let pcap_size_limit = None in
  let pcap_m = Lwt_mutex.create () in
  let listeners = [] in
  let listening = false in
  let after_disconnect, after_disconnect_u = Lwt.task () in
  { fd; stats; client_macaddr; client_uuid; server_macaddr; mtu; write_header; write_m; pcap;
    pcap_size_limit; pcap_m; listeners; listening; after_disconnect; after_disconnect_u }

type fd = C.flow

let of_fd ~client_macaddr_of_uuid ~server_macaddr ~mtu flow =
  let open Lwt_result.Infix in
  let channel = Channel.create flow in
  server_negotiate ~fd:channel ~client_macaddr_of_uuid ~mtu >>= fun (client_uuid, client_macaddr) ->
  let t = make ~client_macaddr ~server_macaddr ~mtu ~client_uuid channel in
  Lwt_result.return t

let client_of_fd ~uuid ~server_macaddr flow =
  let open Lwt_result.Infix in
  let channel = Channel.create flow in
  client_negotiate ~uuid ~fd:channel 
  >>= fun vif ->
  let t = make vif.client_macaddr server_macaddr vif.mtu uuid channel in
  Lwt_result.return t

let disconnect t = match t.fd with
  | None -> Lwt.return ()
  | Some fd ->
    t.fd <- None;
    Log.debug (fun f -> f "Vmnet.disconnect flushing channel");
    Channel.flush fd
    >>= fun () ->
    Lwt.wakeup_later t.after_disconnect_u ();
    Lwt.return ()

let after_disconnect t = t.after_disconnect

let capture t bufs =
  match t.pcap with
  | None -> Lwt.return ()
  | Some pcap ->
    Lwt_mutex.with_lock t.pcap_m
      (fun () ->
         let len = List.(fold_left (+) 0 (map Cstruct.len bufs)) in
         let time = Unix.gettimeofday () in
         let secs = Int32.of_float time in
         let usecs = Int32.of_float (1e6 *. (time -. (floor time))) in
         let buf = Cstruct.create Pcap.sizeof_pcap_packet in
         let open Pcap.LE in
         set_pcap_packet_ts_sec buf secs;
         set_pcap_packet_ts_usec buf usecs;
         set_pcap_packet_incl_len buf @@ Int32.of_int len;
         set_pcap_packet_orig_len buf @@ Int32.of_int len;
         really_write pcap (Cstruct.to_string buf);
         List.iter (fun buf -> really_write pcap (Cstruct.to_string buf)) bufs;
         match t.pcap_size_limit with
         | None -> Lwt.return () (* no limit *)
         | Some limit ->
           let limit = Int64.(sub limit (of_int len)) in
           t.pcap_size_limit <- Some limit;
           if limit < 0L
           then stop_capture_already_locked t
           else Lwt.return ()
      )

let drop_on_error f = Lwt.catch f (fun _ -> Lwt.return ())


let writev t bufs =
  Lwt_mutex.with_lock t.write_m
    (fun () ->
      drop_on_error
        (fun () ->
           capture t bufs
           >>= fun () ->
           let len = List.(fold_left (+) 0 (map Cstruct.len bufs)) in
           if len > (t.mtu + ethernet_header_length) then begin
             Log.err (fun f ->
               f "Dropping over-large ethernet frame, length = %d, mtu = %d" len t.mtu
             );
             Lwt.return_unit
           end else begin
             let buf = Cstruct.create Packet.sizeof in
             Packet.marshal len buf;
             let fd = get_fd t in
             Channel.write_buffer fd buf;
             Log.debug (fun f ->
                 let b = Buffer.create 128 in
                 List.iter (Cstruct.hexdump_to_buffer b) bufs;
                 f "sending\n%s" (Buffer.contents b)
               );
            List.iter (Channel.write_buffer fd) bufs;
            Channel.flush fd
           end
         )
    )

let listen t callback =
  if t.listening then begin
    Log.debug (fun f -> f "PPP.listen: called a second time: doing nothing");
    Lwt.return ();
  end else begin
    t.listening <- true;
    let last_error_log = ref 0. in
    let rec loop () =
      let open Lwt_result.Infix in
      Lwt.catch
        (fun () ->
           let open Lwt.Infix in
           let fd = get_fd t in
           Channel.read_exactly ~len:Packet.sizeof fd
           >>= fun bufs ->
           let read_header = Cstruct.concat bufs in
           let open Lwt_result.Infix in
           Lwt.return (Packet.unmarshal read_header)
           >>= fun (len, _) ->
           let open Lwt.Infix in
           Channel.read_exactly ~len fd
           >>= fun bufs ->
           capture t bufs
           >>= fun () ->
           Log.debug (fun f ->
               let b = Buffer.create 128 in
               List.iter (Cstruct.hexdump_to_buffer b) bufs;
               f "received\n%s" (Buffer.contents b)
             );
           let buf = Cstruct.concat bufs in
           let callback buf =
             Lwt.catch (fun () -> callback buf)
               (fun e ->
                 let now = Unix.gettimeofday () in
                 if (now -. !last_error_log) > 30. then begin
                   Log.err (fun f -> f "PPP.listen callback caught %s" (Printexc.to_string e));
                   last_error_log := now;
                 end;
                 Lwt.return_unit
                ) in
           Lwt.async (fun () -> callback buf);
           List.iter (fun callback -> Lwt.async (fun () -> callback buf)) t.listeners;
           Lwt_result.return true
        ) (function
            | End_of_file ->
              Log.debug (fun f -> f "PPP.listen: closing connection");
              Lwt_result.return false
            | e ->
              Log.err (fun f -> f "PPP.listen: caught unexpected %s: disconnecting" (Printexc.to_string e));
              let open Lwt.Infix in
              disconnect t
              >>= fun () ->
              Lwt_result.return false
          )
      >>= fun continue ->
      if continue then loop () else Lwt_result.return () in
    Lwt.async @@ loop;
    Lwt.return ();
  end


let write t buf =
  Lwt_mutex.with_lock t.write_m
    (fun () ->
      drop_on_error
        (fun () ->
           capture t [ buf ]
           >>= fun () ->
           let len = Cstruct.len buf in
           if len > (t.mtu + ethernet_header_length) then begin
             Log.err (fun f ->
               f "Dropping over-large ethernet frame, length = %d, mtu = %d" len t.mtu
             );
             Lwt.return_unit
           end else begin
             if Cstruct.len t.write_header < Packet.sizeof then begin
               t.write_header <- Cstruct.create (1024 * Packet.sizeof)
             end;
             Packet.marshal len t.write_header;
             let fd = get_fd t in
             Channel.write_buffer fd (Cstruct.sub t.write_header 0 Packet.sizeof);
             t.write_header <- Cstruct.shift t.write_header Packet.sizeof;
             Log.debug (fun f ->
                 let b = Buffer.create 128 in
                 Cstruct.hexdump_to_buffer b buf;
                 f "sending\n%s" (Buffer.contents b)
               );
             Channel.write_buffer fd buf;
             Channel.flush fd
           end
        )
    )

let add_listener t callback =
  t.listeners <- callback :: t.listeners

let mac t = t.server_macaddr

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

let get_id _ = ()
end

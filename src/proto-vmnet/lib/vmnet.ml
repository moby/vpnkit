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

module type CONN = sig
  include V1_LWT.FLOW

  val read_into: flow -> Cstruct.t -> [ `Eof | `Ok of unit ] Lwt.t
  (** Completely fills the given buffer with data from [fd] *)
end

let default_mtu = 1500

let ethernet_header_length = 14 (* no VLAN *)

module Init = struct

  cstruct msg {
      uint8_t magic[5];   (* VMN3T *)
      uint32_t version;   (* 1 *)
      uint8_t commit[40];
    } as little_endian

  type t = {
    magic: string;
    version: int32;
    commit: string;
  } with sexp

  let to_string t = Sexplib.Sexp.to_string (sexp_of_t t)

  let sizeof = sizeof_msg

  let default = {
    magic = "VMN3T";
    version = 1l;
    commit = "0123456789012345678901234567890123456789";
  }

  let marshal t rest =
    set_msg_magic t.magic 0 rest;
    set_msg_version rest t.version;
    set_msg_commit t.commit 0 rest;
    Cstruct.shift rest sizeof_msg

  let unmarshal rest =
    let magic = Cstruct.to_string @@ get_msg_magic rest in
    let version = get_msg_version rest in
    let commit = Cstruct.to_string @@ get_msg_commit rest in
    let rest = Cstruct.shift rest sizeof_msg in
    `Ok ({ magic; version; commit }, rest)
end

module Command = struct

  cstruct msg {
      uint8_t command;
    } as little_endian

  type t =
    | Ethernet of string (* 36 bytes *)
    | Bind_ipv4 of Ipaddr.V4.t * int * bool
  with sexp

  let to_string t = Sexplib.Sexp.to_string (sexp_of_t t)

  let sizeof = sizeof_msg + 36

  let marshal t rest = match t with
    | Ethernet uuid ->
      set_msg_command rest 1;
      let rest = Cstruct.shift rest sizeof_msg in
      Cstruct.blit_from_string uuid 0 rest 0 (String.length uuid);
      Cstruct.shift rest (String.length uuid)
    | Bind_ipv4 (ip, port, stream) ->
      set_msg_command rest 6;
      let rest = Cstruct.shift rest sizeof_msg in
      Cstruct.LE.set_uint32 rest 0 (Ipaddr.V4.to_int32 ip);
      let rest = Cstruct.shift rest 4 in
      Cstruct.LE.set_uint16 rest 0 port;
      let rest = Cstruct.shift rest 2 in
      Cstruct.set_uint8 rest 0 (if stream then 0 else 1);
      Cstruct.shift rest 1

  let unmarshal rest =
    match get_msg_command rest with
    | 1 ->
      let uuid = Cstruct.(to_string (sub rest 1 36)) in
      let rest = Cstruct.shift rest 37 in
      `Ok (Ethernet uuid, rest)
    | n -> `Error (`Msg (Printf.sprintf "Unknown command: %d" n))
end

module Vif = struct
  cstruct msg {
      uint16_t mtu;
      uint16_t max_packet_size;
      uint8_t macaddr[6];
    } as little_endian

  type t = {
    mtu: int;
    max_packet_size: int;
    client_macaddr: Macaddr.t;
  } with sexp

  let to_string t = Sexplib.Sexp.to_string (sexp_of_t t)

  let create client_macaddr () =
    let mtu = default_mtu in
    let max_packet_size = 1550 in
    { mtu; max_packet_size; client_macaddr }

  let sizeof = sizeof_msg

  let marshal t rest =
    set_msg_mtu rest t.mtu;
    set_msg_max_packet_size rest t.max_packet_size;
    set_msg_macaddr (Macaddr.to_bytes t.client_macaddr) 0 rest;
    Cstruct.shift rest sizeof_msg

  let unmarshal rest =
    let mtu = get_msg_mtu rest in
    let max_packet_size = get_msg_max_packet_size rest in
    try
      let client_macaddr = Macaddr.of_bytes_exn @@ Cstruct.to_string @@ get_msg_macaddr rest in
      `Ok ({ mtu; max_packet_size; client_macaddr }, Cstruct.shift rest sizeof_msg)
    with _ ->
      `Error (`Msg (Printf.sprintf "Failed to parse MAC: [%s]" (Cstruct.to_string @@ get_msg_macaddr rest)))

end

module Packet = struct
  cstruct msg {
      uint16_t len;
    } as little_endian

  let sizeof = sizeof_msg

  let marshal t rest =
    set_msg_len rest t

  let unmarshal rest =
    let t = get_msg_len rest in
    `Ok (t, Cstruct.shift rest sizeof)
end

module Infix = struct
  let ( >>= ) m f = m >>= function
    | `Ok x -> f x
    | `Error x -> Lwt.return (`Error x)
end

module Make(C: CONN) = struct
type stats = {
  mutable rx_bytes: int64;
  mutable rx_pkts: int32;
  mutable tx_bytes: int64;
  mutable tx_pkts: int32;
}

type t = {
  mutable fd: C.flow option;
  stats: stats;
  client_macaddr: Macaddr.t;
  server_macaddr: Macaddr.t;
  read_header: Cstruct.t;
  write_header: Cstruct.t;
  write_m: Lwt_mutex.t;
  mutable pcap: Lwt_unix.file_descr option;
  mutable pcap_size_limit: int64 option;
  pcap_m: Lwt_mutex.t;
  mutable listeners: (Cstruct.t -> unit Lwt.t) list;
  mutable listening: bool;
}


let error_of_failure f = Lwt.catch f (fun e -> Lwt.return (`Error (`Msg (Printexc.to_string e))))

let get_fd t = match t.fd with
  | Some fd -> fd
  | None -> failwith "Vmnet connection is disconnected"

let read fd buf =
  C.read_into fd buf
  >>= function
  | `Eof -> Lwt.fail End_of_file
  | `Ok () -> Lwt.return ()

let write fd buf =
  C.write fd buf
  >>= function
  | `Eof -> Lwt.fail End_of_file
  | `Error e -> Lwt.fail (Failure (C.error_message e))
  | `Ok () -> Lwt.return ()

let server_negotiate t =
  error_of_failure
    (fun () ->
      let fd = get_fd t in
      let buf = Cstruct.create Init.sizeof in
      read fd buf
      >>= fun () ->
      let open Infix in
      Lwt.return (Init.unmarshal buf)
      >>= fun (init, _) ->
      Log.info (fun f -> f "PPP.negotiate: received %s" (Init.to_string init));
      let (_: Cstruct.t) = Init.marshal Init.default buf in
      let open Lwt.Infix in
      write fd buf
      >>= fun () ->
      let buf = Cstruct.create Command.sizeof in
      read fd buf
      >>= fun () ->
      let open Infix in
      Lwt.return (Command.unmarshal buf)
      >>= fun (command, _) ->
      Log.info (fun f -> f "PPP.negotiate: received %s" (Command.to_string command));
      let vif = Vif.create t.client_macaddr () in
      let buf = Cstruct.create Vif.sizeof in
      let (_: Cstruct.t) = Vif.marshal vif buf in
      let open Lwt.Infix in
      Log.info (fun f -> f "PPP.negotiate: sending %s" (Vif.to_string vif));
      write fd buf
      >>= fun () ->
      Lwt.return (`Ok ())
    )

let client_negotiate t =
  error_of_failure
    (fun () ->
      let open Lwt.Infix in
      let fd = get_fd t in
      let buf = Cstruct.create Init.sizeof in
      let (_: Cstruct.t) = Init.marshal Init.default buf in
      write fd buf
      >>= fun () ->
      read fd buf
      >>= fun () ->
      let open Infix in
      Lwt.return (Init.unmarshal buf)
      >>= fun (init, _) ->
      Log.info (fun f -> f "Client.negotiate: received %s" (Init.to_string init));
      let buf = Cstruct.create Command.sizeof in
      let uuid = String.make 36 'X' in
      let (_: Cstruct.t) = Command.marshal (Command.Ethernet uuid) buf in
      let open Lwt.Infix in
      write fd buf
      >>= fun () ->
      let buf = Cstruct.create Vif.sizeof in
      read fd buf
      >>= fun () ->
      let open Infix in
      Lwt.return (Vif.unmarshal buf)
      >>= fun (vif, _) ->
      Log.info (fun f -> f "Client.negotiate: vif %s" (Vif.to_string vif));
      Lwt.return (`Ok ())
    )

let start_capture t ?size_limit filename =
  Lwt_mutex.with_lock t.pcap_m
    (fun () ->
      ( match t.pcap with
        | Some fd ->
          Lwt_unix.close fd
        | None ->
          Lwt.return ()
      ) >>= fun () ->
      Lwt_unix.openfile filename [ Unix.O_WRONLY; Unix.O_TRUNC; Unix.O_CREAT ] 0o0644
      >>= fun fd ->
      let buf = Cstruct.create Pcap.LE.sizeof_pcap_header in
      let open Pcap.LE in
      set_pcap_header_magic_number buf Pcap.magic_number;
      set_pcap_header_version_major buf Pcap.major_version;
      set_pcap_header_version_minor buf Pcap.minor_version;
      set_pcap_header_thiszone buf 0l;
      set_pcap_header_sigfigs buf 4l;
      set_pcap_header_snaplen buf 1500l;
      set_pcap_header_network buf (Pcap.Network.to_int32 Pcap.Network.Ethernet);
      Lwt_cstruct.(complete (write fd) buf)
      >>= fun () ->
      t.pcap <- Some fd;
      t.pcap_size_limit <- size_limit;
      Lwt.return ()
    )

let stop_capture_already_locked t = match t.pcap with
  | None -> Lwt.return ()
  | Some fd ->
    Lwt_unix.close fd
    >>= fun () ->
    t.pcap <- None;
    t.pcap_size_limit <- None;
    Lwt.return ()

let stop_capture t =
  Lwt_mutex.with_lock t.pcap_m
    (fun () ->
      stop_capture_already_locked t
    )

let make ~client_macaddr ~server_macaddr fd =
  let fd = Some fd in
  let stats = { rx_bytes = 0L; rx_pkts = 0l; tx_bytes = 0L; tx_pkts = 0l } in
  let read_header = Cstruct.create Packet.sizeof in
  let write_header = Cstruct.create Packet.sizeof in
  let write_m = Lwt_mutex.create () in
  let pcap = None in
  let pcap_size_limit = None in
  let pcap_m = Lwt_mutex.create () in
  let listeners = [] in
  let listening = false in
  { fd; stats; client_macaddr; server_macaddr; read_header; write_header; write_m; pcap; pcap_size_limit; pcap_m; listeners; listening }

type fd = C.flow

let of_fd ~client_macaddr ~server_macaddr fd =
  let open Infix in
  let t = make ~client_macaddr ~server_macaddr fd in
  server_negotiate t
  >>= fun () ->
  Lwt.return (`Ok t)

let client_of_fd ~client_macaddr ~server_macaddr fd =
  let open Infix in
  let t = make ~client_macaddr ~server_macaddr fd in
  client_negotiate t
  >>= fun () ->
  Lwt.return (`Ok t)

let disconnect t = match t.fd with
  | None -> Lwt.return ()
  | Some fd ->
    t.fd <- None;
    Log.info (fun f -> f "Vmnet.disconnect closing fd");
    C.close fd

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
         Lwt_cstruct.(complete (write pcap) buf)
         >>= fun () ->
         let rec loop = function
           | [] -> Lwt.return ()
           | buf :: bufs ->
             Lwt_cstruct.(complete (write pcap) buf)
             >>= fun () ->
             loop bufs in
         loop bufs
         >>= fun () ->
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
           if len > (default_mtu + ethernet_header_length) then begin
             Log.err (fun f ->
               f "Dropping over-large ethernet frame, length = %d, mtu = %d" len default_mtu
             );
             Lwt.return_unit
           end else begin
             Packet.marshal len t.write_header;
             let fd = get_fd t in
             write fd t.write_header
             >>= fun () ->
             Log.debug (fun f ->
                 let b = Buffer.create 128 in
                 List.iter (Cstruct.hexdump_to_buffer b) bufs;
                 f "sending\n%s" (Buffer.contents b)
               );
             let rec loop = function
               | [] -> Lwt.return ()
               | buf :: bufs ->
                 write fd buf
                 >>= fun () ->
                 loop bufs in
             loop bufs
           end
         )
    )

let listen t callback =
  if t.listening then begin
    Log.info (fun f -> f "PPP.listen: called a second time: doing nothing");
    Lwt.return ();
  end else begin
    t.listening <- true;
    let rec loop () =
      let open Infix in
      Lwt.catch
        (fun () ->
           let open Lwt.Infix in
           let fd = get_fd t in
           read fd t.read_header
           >>= fun () ->
           let open Infix in
           Lwt.return (Packet.unmarshal t.read_header)
           >>= fun (len, _) ->
           let buf = Cstruct.create len in
           let open Lwt.Infix in
           read fd buf
           >>= fun () ->
           capture t [ buf ]
           >>= fun () ->
           Log.debug (fun f ->
               let b = Buffer.create 128 in
               Cstruct.hexdump_to_buffer b buf;
               f "received\n%s" (Buffer.contents b)
             );
           let callback buf = log_exception_continue "PPP.listen callback" (fun () -> callback buf) in
           Lwt.async (fun () -> callback buf);
           List.iter (fun callback -> Lwt.async (fun () -> callback buf)) t.listeners;
           Lwt.return (`Ok true)
        ) (function
            | End_of_file ->
              Log.info (fun f -> f "PPP.listen: closing connection");
              Lwt.return (`Ok false);
            | e ->
              Log.err (fun f -> f "PPP.listen: caught unexpected %s: disconnecting" (Printexc.to_string e));
              let open Lwt.Infix in
              disconnect t
              >>= fun () ->
              Lwt.return (`Ok false)
          )
      >>= fun continue ->
      if continue then loop () else Lwt.return (`Ok ()) in
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
           if len > (default_mtu + ethernet_header_length) then begin
             Log.err (fun f ->
               f "Dropping over-large ethernet frame, length = %d, mtu = %d" len default_mtu
             );
             Lwt.return_unit
           end else begin
             Packet.marshal len t.write_header;
             let fd = get_fd t in
             write fd t.write_header
             >>= fun () ->
             Log.debug (fun f ->
                 let b = Buffer.create 128 in
                 Cstruct.hexdump_to_buffer b buf;
                 f "sending\n%s" (Buffer.contents b)
               );
             write fd buf
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

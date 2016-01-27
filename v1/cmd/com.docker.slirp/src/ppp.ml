(*
 * Copyright (C) 2016 David Scott <dave.scott@docker.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)
open Lwt
open Sexplib.Std

(* Assign the client a single MAC address *)
let macaddr = Macaddr.of_string_exn "C0:FF:EE:C0:FF:EE"

let src =
	let src = Logs.Src.create "ppp" ~doc:"point-to-point network link" in
	Logs.Src.set_level src (Some Logs.Info);
	src

module Log = (val Logs.src_log src : Logs.LOG)

type stats = {
  mutable rx_bytes: int64;
  mutable rx_pkts: int32;
  mutable tx_bytes: int64;
  mutable tx_pkts: int32;
}

type t = {
	fd: Lwt_unix.file_descr;
	stats: stats;
	macaddr: Macaddr.t;
	read_header: Cstruct.t;
	write_header: Cstruct.t;
	write_m: Lwt_mutex.t;
	pcap: Lwt_unix.file_descr option;
	pcap_m: Lwt_mutex.t;
	mutable listeners: (Cstruct.t -> unit Lwt.t) list;
	mutable listening: bool;
}

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
	with sexp

	let to_string t = Sexplib.Sexp.to_string (sexp_of_t t)

	let sizeof = sizeof_msg + 36

	let marshal t rest = match t with
	  | Ethernet uuid ->
		  set_msg_command rest 1;
			let rest = Cstruct.shift rest sizeof_msg in
			Cstruct.blit_from_string uuid 0 rest 0 (String.length uuid);
			Cstruct.shift rest (String.length uuid)

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
		macaddr: Macaddr.t;
	} with sexp

	let to_string t = Sexplib.Sexp.to_string (sexp_of_t t)

	let create () =
		let mtu = 1500 in
		let max_packet_size = 1550 in
		{ mtu; max_packet_size; macaddr }

	let sizeof = sizeof_msg

  let marshal t rest =
	  set_msg_mtu rest t.mtu;
		set_msg_max_packet_size rest t.max_packet_size;
		set_msg_macaddr (Macaddr.to_bytes t.macaddr) 0 rest;
		Cstruct.shift rest sizeof_msg

	let unmarshal rest =
	  let mtu = get_msg_mtu rest in
		let max_packet_size = get_msg_max_packet_size rest in
		try
			let macaddr = Macaddr.of_string_exn @@ Cstruct.to_string @@ get_msg_macaddr rest in
			`Ok ({ mtu; max_packet_size; macaddr }, Cstruct.shift rest sizeof_msg)
		with _ ->
			`Error (`Msg "Failed to parse MAC")

end

module Packet = struct
  cstruct msg {
		uint16_t len;
	} as little_endian

  type t = int

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

let negotiate t =
  let buf = Cstruct.create Init.sizeof in
	Lwt_cstruct.(complete (read t.fd) buf)
	>>= fun () ->
	let open Infix in
	Lwt.return (Init.unmarshal buf)
	>>= fun (init, _) ->
	Log.info (fun f -> f "received %s" (Init.to_string init));
	let (_: Cstruct.t) = Init.marshal Init.default buf in
	let open Lwt.Infix in
	Lwt_cstruct.(complete (write t.fd) buf)
	>>= fun () ->
	let buf = Cstruct.create Command.sizeof in
	Lwt_cstruct.(complete (read t.fd) buf)
	>>= fun () ->
	let open Infix in
	Lwt.return (Command.unmarshal buf)
	>>= fun (command, _) ->
	Log.info (fun f -> f "received %s" (Command.to_string command));
	let vif = Vif.create () in
	let buf = Cstruct.create Vif.sizeof in
	let (_: Cstruct.t) = Vif.marshal vif buf in
	let open Lwt.Infix in
	Log.info (fun f -> f "sending %s" (Vif.to_string vif));
	Lwt_cstruct.(complete (write t.fd) buf)
	>>= fun () ->
	Lwt.return (`Ok ())

let pcap_header = {
	Pcap.magic_number = Pcap.magic_number;
	endian = Pcap.Little;
	version_major = Pcap.major_version;
	version_minor = Pcap.minor_version;
	timezone = 0l;   (* GMT to local correction *)
	sigfigs = 4l;    (* accuracy of timestamps *)
	snaplen = 1500l; (* max length of captured packets, in octets *)
	network = Pcap.Network.to_int32 Pcap.Network.Ethernet;
}

let of_fd ?pcap_filename fd =
	( match pcap_filename with
		| None -> Lwt.return None
		| Some filename ->
			Lwt_unix.openfile filename [ Unix.O_WRONLY; Unix.O_TRUNC; Unix.O_CREAT ] 0o0644
			>>= fun fd ->
			let buf = Cstruct.create Pcap.sizeof_pcap_header in
			let open Pcap in
			let open Pcap.LE in
			set_pcap_header_magic_number buf pcap_header.magic_number;
			set_pcap_header_version_major buf pcap_header.version_major;
			set_pcap_header_version_minor buf pcap_header.version_minor;
			set_pcap_header_thiszone buf pcap_header.timezone; (* NB different name *)
			set_pcap_header_sigfigs buf pcap_header.sigfigs;
			set_pcap_header_snaplen buf pcap_header.snaplen;
			set_pcap_header_network buf pcap_header.network;
			Lwt_cstruct.(complete (write fd) buf)
			>>= fun () ->
			Lwt.return (Some fd) )
	>>= fun pcap ->
	let open Infix in
	let stats = { rx_bytes = 0L; rx_pkts = 0l; tx_bytes = 0L; tx_pkts = 0l } in
	let read_header = Cstruct.create Packet.sizeof in
	let write_header = Cstruct.create Packet.sizeof in
	let write_m = Lwt_mutex.create () in
	let pcap_m = Lwt_mutex.create () in
	let listeners = [] in
	let listening = false in
	let t = { fd; stats; macaddr; read_header; write_header; write_m; pcap; pcap_m; listeners; listening } in
	negotiate t
	>>= fun () ->
	Lwt.return (`Ok t)

let disconnect t =
  Lwt_unix.close t.fd

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
				let open Pcap in
				let open Pcap.LE in
				set_pcap_packet_ts_sec buf secs;
				set_pcap_packet_ts_usec buf usecs;
				set_pcap_packet_caplen buf @@ Int32.of_int len;
				set_pcap_packet_len buf @@ Int32.of_int len;
				Lwt_cstruct.(complete (write pcap) buf)
				>>= fun () ->
				let rec loop = function
				  | [] -> Lwt.return ()
					| buf :: bufs ->
						Lwt_cstruct.(complete (write pcap) buf)
						>>= fun () ->
						loop bufs in
				loop bufs
			)

let write t buf =
	Lwt_mutex.with_lock t.write_m
		(fun () ->
			capture t [ buf ]
			>>= fun () ->
			let len = Cstruct.len buf in
			Packet.marshal len t.write_header;
			Lwt_cstruct.(complete (write t.fd) t.write_header)
			>>= fun () ->
			Log.debug (fun f ->
				let b = Buffer.create 128 in
				Cstruct.hexdump_to_buffer b buf;
				f "sending\n%s" (Buffer.contents b)
			);
			Lwt_cstruct.(complete (write t.fd) buf)
		)

let writev t bufs =
	Lwt_mutex.with_lock t.write_m
	  (fun () ->
			capture t bufs
			>>= fun () ->
			let len = List.(fold_left (+) 0 (map Cstruct.len bufs)) in
			Packet.marshal len t.write_header;
			Lwt_cstruct.(complete (write t.fd) t.write_header)
			>>= fun () ->
			Log.debug (fun f ->
				let b = Buffer.create 128 in
				List.iter (Cstruct.hexdump_to_buffer b) bufs;
				f "sending\n%s" (Buffer.contents b)
			);
			let rec loop = function
			  | [] -> Lwt.return ()
				| buf :: bufs ->
				  Lwt_cstruct.(complete (write t.fd) buf)
					>>= fun () ->
					loop bufs in
			loop bufs
		)

let listen t callback =
  if t.listening then begin
		Log.warn (fun f -> f "Usernet_ppp.listen called a second time: doing nothing");
		Lwt.return ();
	end else begin
		t.listening <- true;
		let rec loop () =
			let open Infix in
			Lwt.catch
			  (fun () ->
					let open Lwt.Infix in
				  Lwt_cstruct.(complete (read t.fd) t.read_header)
					>>= fun () ->
					let open Infix in
					Lwt.return (Packet.unmarshal t.read_header)
					>>= fun (len, _) ->
					let buf = Cstruct.create len in
					let open Lwt.Infix in
					Lwt_cstruct.(complete (read t.fd) buf)
					>>= fun () ->
					capture t [ buf ]
					>>= fun () ->
					Log.debug (fun f ->
						let b = Buffer.create 128 in
						Cstruct.hexdump_to_buffer b buf;
						f "received\n%s" (Buffer.contents b)
					);
					Lwt.async (fun () -> callback buf);
					List.iter (fun callback -> Lwt.async (fun () -> callback buf)) t.listeners;
					Lwt.return (`Ok true)
				) (fun e ->
					Log.err (fun f -> f "usernet_ppp.listen caught %s" (Printexc.to_string e));
					let open Lwt.Infix in
					Lwt_unix.close t.fd
					>>= fun () ->
					Lwt.return (`Ok false)
				)
			>>= fun continue ->
			if continue then loop () else Lwt.return (`Ok ()) in
		Lwt.async @@ loop;
		Lwt.return ();
	end

let add_listener t callback =
	t.listeners <- callback :: t.listeners

let mac t = t.macaddr

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

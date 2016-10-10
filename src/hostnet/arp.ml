(*
 * Copyright (C) 2016 David Scott <dave.scott@docker.com>
 *
 * based on mirage-tcpip/lib/arpv4.ml which is
 *
 * Copyright (c) 2010-2011 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) Hannes Mehnert <hannes@mehnert.org>
 * Copyright (c) Mindy Preston <meetup@yomimono.org>
 * Copyright (c) Thomas Gazagnaire <thomas@gazagnaire.org>
 * Copyright (c) Nicolas Ojeda Bar <n.oje.bar@gmail.com>
 * Copyright (c) Thomas Leonard <talex5@gmail.com>
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

let src =
  let src = Logs.Src.create "arp" ~doc:"fixed ARP table" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Make(Ethif: V1_LWT.ETHIF) = struct
  type 'a io = 'a Lwt.t

  type ipaddr = Ipaddr.V4.t
  type buffer = Cstruct.t
  type macaddr = Macaddr.t
  module Table = Map.Make(Ipaddr.V4)
  type t = {
    ethif: Ethif.t;
    mutable table: macaddr Table.t;
  }
  type error = unit
  type id = unit

  type repr = string

  type result = [ `Ok of macaddr | `Timeout ]
  let to_repr t =
    Lwt.return (String.concat "; " (List.map (fun (ip, mac) -> Printf.sprintf "%s -> %s" (Ipaddr.V4.to_string ip) (Macaddr.to_string mac)) (Table.bindings t.table)))
  let pp fmt repr =
    Format.fprintf fmt "%s" repr

  let get_ips t = List.map fst (Table.bindings t.table)
  let add_ip t ip =
    let mac = Ethif.mac t.ethif in
    Log.info (fun f -> f "ARP: adding %s -> %s" (Ipaddr.V4.to_string ip) (Macaddr.to_string mac));
    Lwt.return_unit
  let set_ips t ips = Lwt_list.iter_s (add_ip t) ips
  let remove_ip t ip =
    Log.info (fun f -> f "ARP: removing %s" (Ipaddr.V4.to_string ip));
    t.table <- Table.remove ip t.table;
    Lwt.return_unit
  let query t ip =
    if Table.mem ip t.table
    then Lwt.return (`Ok (Table.find ip t.table))
    else begin
      Log.warn (fun f -> f "ARP table has no entry for %s" (Ipaddr.V4.to_string ip));
      Lwt.return `Timeout
    end

  type arp = {
      op: [ `Request |`Reply |`Unknown of int ];
      sha: Macaddr.t;
      spa: Ipaddr.V4.t;
      tha: Macaddr.t;
      tpa: Ipaddr.V4.t;
    }

  let rec input t frame =
    let open Arpv4_wire in
    match get_arp_op frame with
    |1 -> (* Request *)
      let req_ipv4 = Ipaddr.V4.of_int32 (get_arp_tpa frame) in
      if Table.mem req_ipv4 t.table then begin
        Log.debug (fun f -> f "ARP responding to: who-has %s?" (Ipaddr.V4.to_string req_ipv4));
        let sha = Table.find req_ipv4 t.table in
        let tha = Macaddr.of_bytes_exn (copy_arp_sha frame) in
        let spa = Ipaddr.V4.of_int32 (get_arp_tpa frame) in (* the requested address *)
        let tpa = Ipaddr.V4.of_int32 (get_arp_spa frame) in (* the requesting host IPv4 *)
        output t { op=`Reply; sha; tha; spa; tpa }
      end else Lwt.return_unit
    |2 -> (* Reply *)
      let spa = Ipaddr.V4.of_int32 (get_arp_tpa frame) in (* the requested address *)
      Log.debug (fun f -> f "ARP ignoring reply %s" (Ipaddr.V4.to_string spa));
      Lwt.return_unit
    |n ->
      Log.debug (fun f -> f "ARP: Unknown message %d ignored" n);
      Lwt.return_unit

  and output t arp =
    let open Arpv4_wire in
    (* Obtain a buffer to write into *)
    let buf = Io_page.to_cstruct (Io_page.get 1) in
    (* Write the ARP packet *)
    let dmac = Macaddr.to_bytes arp.tha in
    let smac = Macaddr.to_bytes arp.sha in
    let spa = Ipaddr.V4.to_int32 arp.spa in
    let tpa = Ipaddr.V4.to_int32 arp.tpa in
    let op =
      match arp.op with
      |`Request -> 1
      |`Reply -> 2
      |`Unknown n -> n
    in
    Wire_structs.set_ethernet_dst dmac 0 buf;
    Wire_structs.set_ethernet_src smac 0 buf;
    Wire_structs.set_ethernet_ethertype buf 0x0806; (* ARP *)
    let arpbuf = Cstruct.shift buf 14 in
    set_arp_htype arpbuf 1;
    set_arp_ptype arpbuf 0x0800; (* IPv4 *)
    set_arp_hlen arpbuf 6; (* ethernet mac size *)
    set_arp_plen arpbuf 4; (* ipv4 size *)
    set_arp_op arpbuf op;
    set_arp_sha smac 0 arpbuf;
    set_arp_spa arpbuf spa;
    set_arp_tha dmac 0 arpbuf;
    set_arp_tpa arpbuf tpa;
    (* Resize buffer to sizeof arp packet *)
    let buf = Cstruct.sub buf 0 (sizeof_arp + Wire_structs.sizeof_ethernet) in
    Ethif.write t.ethif buf

  type ethif = Ethif.t

  let connect ~table ethif =
    let table = List.fold_left (fun acc (ip, mac) -> Table.add ip mac acc) Table.empty table in
    Lwt.return (`Ok { table; ethif })
  let disconnect _t = Lwt.return_unit
end

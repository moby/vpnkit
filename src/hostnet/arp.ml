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
open Lwt.Infix

let src =
  let src = Logs.Src.create "arp" ~doc:"fixed ARP table" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Make (Ethif: Mirage_protocols.ETHERNET) = struct

  module Table = Map.Make(Ipaddr.V4)

  type macaddr = Macaddr.t
  type t = { ethif: Ethif.t; mutable table: macaddr Table.t }
  type error = Mirage_protocols.Arp.error
  let pp_error = Mirage_protocols.Arp.pp_error

  let to_string t =
    let pp_one (ip, mac) =
      Fmt.strf "%s -> %s" (Ipaddr.V4.to_string ip) (Macaddr.to_string mac)
    in
    Table.bindings t.table
    |> List.map pp_one
    |> String.concat "; "

  let pp fmt t = Format.pp_print_string fmt @@ to_string t

  let get_ips t = List.map fst (Table.bindings t.table)

  let add_ip t ip =
    let mac = Ethif.mac t.ethif in
    Log.debug (fun f ->
        f "ARP: adding %s -> %s"
          (Ipaddr.V4.to_string ip) (Macaddr.to_string mac));
    Lwt.return_unit

  let set_ips t ips = Lwt_list.iter_s (add_ip t) ips

  let remove_ip t ip =
    Log.debug (fun f -> f "ARP: removing %s" (Ipaddr.V4.to_string ip));
    t.table <- Table.remove ip t.table;
    Lwt.return_unit

  let query t ip =
    if Table.mem ip t.table
    then Lwt.return (Ok (Table.find ip t.table))
    else begin
      Log.warn (fun f ->
          f "ARP table has no entry for %s" (Ipaddr.V4.to_string ip));
      Lwt.return (Error `Timeout)
    end

  let output t pkt =
    Ethif.write t.ethif ~src:pkt.Arp_packet.source_mac pkt.Arp_packet.target_mac `ARP
      (fun buf ->
        Arp_packet.encode_into pkt buf;
        Arp_packet.size
      )

  let input t frame = match Arp_packet.decode frame with
  | Error err ->
    Log.err (fun f -> f "error while reading ARP packet: %a" Arp_packet.pp_error err);
    Lwt.return_unit
  | Ok ({ Arp_packet.operation = Arp_packet.Reply; _ } as pkt) ->
    Log.debug (fun f -> f "ARP ignoring reply %a" Arp_packet.pp pkt);
    Lwt.return_unit
  | Ok pkt ->
    if Table.mem pkt.target_ip t.table then begin
        Log.debug (fun f ->
            f "ARP responding to: who-has %s?" (Ipaddr.V4.to_string pkt.target_ip));
        let sha = Table.find pkt.target_ip t.table in
        output t {
          Arp_packet.operation = Arp_packet.Reply;
          source_mac = sha;
          source_ip = pkt.target_ip;
          target_ip = pkt.source_ip;
          target_mac = pkt.source_mac;
        } >|= function
        | Ok ()   -> ()
        | Error e ->
          Log.err (fun f ->
              f "error while reading ARP packet: %a" Ethif.pp_error e);
      end else Lwt.return_unit

  type ethif = Ethif.t

  let connect ~table ethif =
    let table =
      List.fold_left (fun acc (ip, mac) ->
          Table.add ip mac acc
        ) Table.empty table
    in
    { table; ethif }

  let disconnect _t = Lwt.return_unit
end

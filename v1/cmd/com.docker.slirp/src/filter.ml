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

let src =
  let src = Logs.Src.create "ppp" ~doc:"point-to-point network link" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Infix = struct
  let ( >>= ) m f = m >>= function
    | `Ok x -> f x
    | `Error x -> Lwt.return (`Error x)
end

module Make(Input: Network.S) = struct

  type stats = {
    mutable rx_bytes: int64;
    mutable rx_pkts: int32;
    mutable tx_bytes: int64;
    mutable tx_pkts: int32;
  }

  type t = {
    input: Input.t;
    stats: stats;
    valid_sources: Ipaddr.V4.t list;
  }

  let connect ~valid_sources input =
    let stats = {
      rx_bytes = 0L; rx_pkts = 0l; tx_bytes = 0L; tx_pkts = 0l;
    } in
    Lwt.return (`Ok { input; stats; valid_sources })

  let disconnect t = Input.disconnect t.input

  let write t buf = Input.write t.input buf
  let writev t bufs = Input.writev t.input bufs

  let filter valid_sources next buf =
    match (Wire_structs.parse_ethernet_frame buf) with
    | Some (Some Wire_structs.IPv4, _, payload) ->
      let src = Ipaddr.V4.of_int32 @@ Wire_structs.Ipv4_wire.get_ipv4_src payload in
      if List.fold_left (fun acc valid -> acc || (Ipaddr.V4.compare src valid = 0)) false valid_sources
      then next buf
      else begin
        let src = Ipaddr.V4.to_string src in
        let dst = Ipaddr.V4.to_string @@ Ipaddr.V4.of_int32 @@ Wire_structs.Ipv4_wire.get_ipv4_dst payload in
        let body = Cstruct.shift payload Wire_structs.Ipv4_wire.sizeof_ipv4 in
        begin match Wire_structs.Ipv4_wire.(int_to_protocol @@ get_ipv4_proto payload) with
          | Some `UDP ->
            let src_port = Wire_structs.get_udp_source_port body in
            let dst_port = Wire_structs.get_udp_dest_port body in
            Log.warn (fun f -> f "dropping unexpected UDP packet sent from %s:%d to %s:%d" src src_port dst dst_port)
          | Some `TCP ->
            let src_port = Wire_structs.Tcp_wire.get_tcp_src_port body in
            let dst_port = Wire_structs.Tcp_wire.get_tcp_dst_port body in
            Log.warn (fun f -> f "dropping unexpected TCP packet sent from %s:%d to %s:%d" src src_port dst dst_port)
          | _ ->
            Log.warn (fun f -> f "dropping unknown IP protocol %d sent from %s to %s" (Wire_structs.Ipv4_wire.get_ipv4_proto payload) src dst)
        end;
        Lwt.return ()
      end
    | _ -> next buf

  let listen t callback = Input.listen t.input @@ filter t.valid_sources callback
  let add_listener t callback = Input.add_listener t.input @@ filter t.valid_sources callback

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

  let get_id _ = ()
end

(*
 * Copyright (c) 2005-2012 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2013 David Sheets <sheets@alum.mit.edu>
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
 *)

open Lwt.Infix

module DR = Dns.RR
module DP = Dns.Packet
module DQ = Dns.Query

type ip_endpoint = Ipaddr.t * int

type 'a process = src:ip_endpoint -> dst:ip_endpoint -> 'a -> Dns.Query.answer option Lwt.t

module type PROCESSOR = sig
  include Dns.Protocol.SERVER
  val process : context process
end

type 'a processor = (module PROCESSOR with type context = 'a)

let compose process backup ~src ~dst packet =
  process ~src ~dst packet
  >>= fun result ->
  match result with
  | Some a ->
      let open DQ in
      (match a.rcode with
      | DP.NoError -> Lwt.return result
      | _ -> backup ~src ~dst packet)
  | None -> backup ~src ~dst packet

let process_query ?alloc buf len src dst processor =
  let module Processor = (val processor : PROCESSOR) in
  match Processor.parse (Cstruct.sub buf 0 len) with
  |None -> Lwt.return_none
  |Some ctxt ->
    Processor.process ~src ~dst ctxt >|= function
    |None -> None
    |Some answer ->
      let query = Processor.query_of_context ctxt in
      let response = Dns.Query.response_of_answer query answer in
      Processor.marshal ?alloc ctxt response

let processor_of_process process : Dns.Packet.t processor =
  let module P = struct
    include Dns.Protocol.Server
    let process = process
  end in
  (module P)

let process_of_zonebufs zonebufs =
  let db = List.fold_left (fun db -> Dns.Zone.load ~db [])
    (Dns.Loader.new_db ()) zonebufs in
  let dnstrie = db.Dns.Loader.trie in
  let get_answer qname qtype _id =
    Dns.Query.answer ~dnssec:true qname qtype dnstrie
  in
  fun ~src:_ ~dst:_ d ->
    let open DP in
    (* TODO: FIXME so that 0 question queries don't crash the server *)
    let q = List.hd d.questions in
    let r =
      Dns.Protocol.contain_exc "answer"
        (fun () -> get_answer q.q_name q.q_type d.id)
    in
    Lwt.return r

let process_of_zonebuf zonebuf =
  process_of_zonebufs [zonebuf]

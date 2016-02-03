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
open Dns

let src =
  let src = Logs.Src.create "dns" ~doc:"Resolve DNS queries on the host" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let resolver_t =
  (* We need to proxy DNS to the host resolver *)
  Dns_resolver_unix.create () (* create resolver using /etc/resolv.conf *)

let input s ~src ~dst ~src_port buf =
  resolver_t
  >>= fun resolver ->

  let process ~src ~dst packet =
    let open Packet in
    match packet.questions with
    | [] -> return None; (* no questions in packet *)
    | [q] ->
      Lwt.catch
        (fun () ->
          Dns_resolver_unix.resolve resolver q.q_class q.q_type q.q_name
          >>= fun result ->
          (return (Some (Dns.Query.answer_of_response result)))
        ) (function
          | Dns.Protocol.Dns_resolve_error exns ->
            Log.err (fun f -> f "DNS resolution failed for %s: %s" (Dns.Packet.question_to_string q) (String.concat "; " (List.map Printexc.to_string exns)));
            return None
          | e ->
            Log.err (fun f -> f "DNS resolution failed for %s: %s" (Dns.Packet.question_to_string q) (Printexc.to_string e));
            return None
          )
    | _::_::_ -> return None in

  let processor = ((Dns_server.processor_of_process process) :> (module Dns_server.PROCESSOR)) in
  let open Dns_server in
  let len = Cstruct.len buf in
  let buf = Dns.Buf.of_cstruct buf in
  let src' = Ipaddr.V4 src, src_port in
  let dst' = Ipaddr.V4 dst, 53 in
  let obuf = Dns.Buf.create 4096 in
  process_query buf len obuf src' dst' processor
  >>= function
  | None -> Lwt.return_unit
  | Some buf ->
    let buf = Cstruct.of_bigarray buf in
    Tcpip_stack.UDPV4.write ~source_port:53 ~dest_ip:src ~dest_port:src_port (Tcpip_stack.udpv4 s) buf

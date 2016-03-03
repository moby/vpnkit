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

(* A queue of responses per source port. Returning results out of order
   seems to confuse the Linux resolver, even though the requests and responses
   have transaction ids *)

type response_sender = unit -> unit Lwt.t

type queue = {
  senders: response_sender Lwt.t Queue.t;
}

let per_source_port : (int, queue) Hashtbl.t = Hashtbl.create 7

let enter_queue src_port =
  let t, u = Lwt.task () in
  if Hashtbl.mem per_source_port src_port then begin
    let q = Hashtbl.find per_source_port src_port in
    Queue.push t q.senders;
  end else begin
    let senders = Queue.create () in
    let q = { senders } in
    Hashtbl.replace per_source_port src_port q;
    Queue.push t q.senders;
    let rec process () =
      if Queue.is_empty q.senders then begin
        Hashtbl.remove per_source_port src_port;
        Lwt.return ()
      end else begin
        let t = Queue.pop q.senders in
        t >>= fun response_sender ->
        response_sender ()
        >>= fun () ->
        process ()
      end in
    let _thread = process () in
    ()
  end;
  u

let input s ~src ~dst ~src_port buf =
  let wakener = enter_queue src_port in

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
  | None ->
    Lwt.wakeup_later wakener (fun () -> Lwt.return_unit);
    Lwt.return_unit
  | Some buf ->
    let buf = Cstruct.of_bigarray buf in
    (* Take a copy of the response buffer to put in the response queue *)
    let copy = Cstruct.create (Cstruct.len buf) in
    Cstruct.blit buf 0 copy 0 (Cstruct.len buf);
    Lwt.wakeup_later wakener
      (fun () ->
        Tcpip_stack.UDPV4.write ~source_port:53 ~dest_ip:src ~dest_port:src_port (Tcpip_stack.udpv4 s) copy
      );
    Lwt.return ()

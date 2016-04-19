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
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module OptionThread = struct
  let (>>=) m f = m >>= function
    | None -> Lwt.return_none
    | Some x -> f x
end

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
  if List.mem dst (Tcpip_stack.IPV4.get_ip (Tcpip_stack.ipv4 s)) then begin
  let wakener = enter_queue src_port in

  (* Re-read /etc/resolv.conf on every request. This ensures that
     changes to DNS on sleep/resume or switching networks are reflected
     immediately. The file is very small, and parsing it shouldn't be
     too slow. *)
  Dns_resolver_unix.create () (* re-read /etc/resolv.conf *)
  >>= fun resolver ->

  let src_str = Ipaddr.V4.to_string src in
  let dst_str = Ipaddr.V4.to_string dst in

  let len = Cstruct.len buf in
  let buf = Dns.Buf.of_cstruct buf in
  let obuf = Dns.Buf.create 4096 in

  let result =
    let open OptionThread in
    ( match Dns.Protocol.Server.parse (Dns.Buf.sub buf 0 len) with
    | None ->
      Log.err (fun f -> f "Failed to parse DNS packet");
      Lwt.return_none
    | Some request ->
      Log.debug (fun f -> f "DNS %s:%d -> %s %s" src_str src_port dst_str (Dns.Packet.to_string request));
      begin match request.Dns.Packet.questions with
      | [] -> Lwt.return_none (* no questions in packet *)
      | [q] ->
        Lwt.catch
          (fun () ->
            let open Lwt.Infix in
            Dns_resolver_unix.resolve resolver q.Dns.Packet.q_class q.Dns.Packet.q_type q.Dns.Packet.q_name
            >>= fun response ->
            Lwt.return (Some (request, { response with Dns.Packet.id = request.Dns.Packet.id }))
          ) (function
            | Dns.Protocol.Dns_resolve_error exns ->
              Log.err (fun f -> f "DNS resolution failed for %s: %s" (Dns.Packet.question_to_string q) (String.concat "; " (List.map Printexc.to_string exns)));
              Lwt.return_none
            | e ->
              Log.err (fun f -> f "DNS resolution failed for %s: %s" (Dns.Packet.question_to_string q) (Printexc.to_string e));
              Lwt.return_none
            )
      | _::_::_ ->
        Log.err (fun f -> f "More than 1 query in DNS request: %s" (Dns.Packet.to_string request));
        Lwt.return_none
      end
    ) >>= fun (request, response) ->
    (* Preserve the ra flag from the response *)
    let ra = response.Dns.Packet.detail.Dns.Packet.ra in

    let query = Dns.Protocol.Server.query_of_context request in
    let answer = Dns.Query.answer_of_response ~preserve_aa:true response in
    let response = Dns.Query.response_of_answer query answer in
    let response = { response with Dns.Packet.detail = { response.Dns.Packet.detail with Dns.Packet.ra }} in
    (* response.Dns.Packet.deail.ra =  true *)
    match Dns.Protocol.Server.marshal obuf request response with
    | None -> Lwt.return_none
    | Some buf -> Lwt.return (Some (response, buf)) in

  result
  >>= function
  | None ->
    Lwt.wakeup_later wakener (fun () -> Lwt.return_unit);
    Lwt.return_unit
  | Some (response, buf) ->
    let buf = Cstruct.of_bigarray buf in
    (* Take a copy of the response buffer to put in the response queue *)
    let copy = Cstruct.create (Cstruct.len buf) in
    Cstruct.blit buf 0 copy 0 (Cstruct.len buf);
    Lwt.wakeup_later wakener
      (fun () ->
        Tcpip_stack.UDPV4.write ~source_port:53 ~dest_ip:src ~dest_port:src_port (Tcpip_stack.udpv4 s) copy
        >>= fun () ->
        Log.debug (fun f -> f "DNS %s:%d <- %s %s" src_str src_port dst_str (Dns.Packet.to_string response));
        Lwt.return ()
      );
    Lwt.return ()
  end else Lwt.return_unit

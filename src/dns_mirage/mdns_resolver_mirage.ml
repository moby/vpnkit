(*
 * Copyright (c) 2015 Luke Dunstan <LukeDunstan81@gmail.com>
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

open Lwt
open Dns
open Operators
open Dns_resolver
open Result

module DP = Dns.Packet

let default_ns = Ipaddr.V4.of_string_exn "224.0.0.251"
let default_port = 5353

module type S = Dns_resolver_mirage.S

module Client : Dns.Protocol.CLIENT = struct
  type context = DP.t

  let get_id () = 0

  let marshal ?alloc q = [q, DP.marshal ?alloc q]

  let packet_matches query packet =
    let open DP in
    let rr_answers_question q rr =
      q.q_name = rr.name &&
      q_type_matches_rr_type q.q_type (rdata_to_rr_type rr.rdata) &&
      q.q_class = Q_IN && rr.cls = RR_IN
    in
    let rec rrlist_answers_question q rrlist =
      match rrlist with
      | [] -> false
      | rr :: tl -> rr_answers_question q rr || rrlist_answers_question q tl
    in
    let rec rrlist_answers_questions qs rrlist =
      match qs with
      | [] -> false
      | q :: tl -> rrlist_answers_question q rrlist || rrlist_answers_questions tl rrlist
    in
    packet.detail.qr = Response &&
      packet.detail.opcode = Standard &&
      packet.detail.rcode = NoError &&
      rrlist_answers_questions query.questions packet.answers

  let parse q buf =
    let pkt = DP.parse buf in
    if packet_matches q pkt then Some pkt else None

  let timeout _id = Dns.Protocol.Dns_resolve_timeout
end

module Make(Time:Mirage_time_lwt.S)(S:Mirage_stack_lwt.V4) = struct

  type stack = S.t
  type endp = Ipaddr.V4.t * int

  type t = {
    s: S.t;
    res: (endp, Dns_resolver.commfn) Hashtbl.t;
  }

  let create s =
    let res = Hashtbl.create 3 in
    { s; res }

  let connect_to_resolver {s; res} ((dst,dst_port) as endp) =
    let udp = S.udpv4 s in
    try
      Hashtbl.find res endp
    with Not_found ->
      let timerfn () = Time.sleep_ns (Duration.of_sec 5) in
      let mvar = Lwt_mvar.create_empty () in
      let src_port = default_port in
      let callback ~src:_ ~dst:_ ~src_port buf =
        (* TODO: ignore responses that are not from the local link *)
        (* Ignore responses that are not from port 5353 *)
        if src_port = dst_port then
          Lwt_mvar.put mvar buf
        else
          return_unit
      in
      let cleanfn () = return () in
      (* FIXME: can't coexist with server yet because both listen on port 5353 *)
      S.listen_udpv4 s ~port:src_port callback;
      let txfn buf =
        S.UDPV4.write ~src_port ~dst ~dst_port udp buf >>= function
        | Error e ->
          Fmt.kstrf fail_with
            "Attempting to communicate with remote resolver: %a"
            S.UDPV4.pp_error e
        | Ok () -> Lwt.return_unit
      in
      let rec rxfn f =
        Lwt_mvar.take mvar
        >>= fun buf ->
        match f buf with
        | None -> rxfn f
        | Some packet -> return packet
      in
      let commfn = { txfn; rxfn; timerfn; cleanfn } in
      Hashtbl.add res endp commfn;
      commfn

  let create_packet q_class q_type q_name =
    let open Dns.Packet in
    let detail = {
      qr=Query; opcode=Standard;
      aa=false; tc=false; rd=false; ra=false; rcode=NoError;
    } in
    let question = { q_name; q_type; q_class; q_unicast=Q_Normal } in
    { id=0; detail; questions=[question];
      answers=[]; authorities=[]; additionals=[];
    }

  let resolve client
      t server dns_port
      (q_class:DP.q_class) (q_type:DP.q_type)
      (q_name:Name.t) =
    let commfn = connect_to_resolver t (server,dns_port) in
    let q = create_packet q_class q_type q_name in
    resolve_pkt client commfn q

  let gethostbyname
      t ?(server = default_ns) ?(dns_port = default_port)
      ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_A)
      name =
    (* TODO: duplicates Dns_resolver.gethostbyname *)
    let open DP in
    let domain = Name.of_string name in
    resolve (module Client) t server dns_port q_class q_type domain
    >|= fun r ->
    List.fold_left (fun a x ->
        match x.rdata with
        | A ip -> Ipaddr.V4 ip :: a
        | AAAA ip -> Ipaddr.V6 ip :: a
        | _ -> a
      ) [] r.answers
    |> List.rev

  let gethostbyaddr
      t ?(server = default_ns) ?(dns_port = default_port)
      ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_PTR)
      addr =
    (* TODO: duplicates Dns_resolver.gethostbyaddr *)
    let addr = Name.of_ipaddr (Ipaddr.V4 addr) in
    let open DP in
    resolve (module Client) t server dns_port q_class q_type addr
    >|= fun r ->
    List.fold_left (fun a x ->
        match x.rdata with |PTR n -> (Name.to_string n)::a |_->a
      ) [] r.answers
    |> List.rev

end

module Chain(Local:S)(Next:S with type stack = Local.stack) = struct
  type t = {
    local: Local.t;
    next: Next.t;
  }
  type stack = Local.stack

  let create stack =
    { local = Local.create stack; next = Next.create stack }

  let rec starts_with labels prefix =
    match labels, prefix with
    | (_l, []) -> true
    | ([], _ph :: _pt) -> false
    | (lh :: lt, ph :: pt) ->
      if lh = ph then
        starts_with lt pt
      else
        false

  let ends_with labels suffix =
    starts_with (List.rev labels) (List.rev suffix)

  let is_local name =
    ends_with (Name.to_string_list name) ["local"]

  let is_link_local name =
    ends_with (Name.to_string_list name) ["254"; "169"; "in-addr"; "arpa"]

  let resolve client
      t server dns_port
      (q_class:DP.q_class) (q_type:DP.q_type)
      (q_name:Name.t) =
    if is_local q_name || is_link_local q_name then
      Local.resolve client t.local server dns_port q_class q_type q_name
    else
      Next.resolve client t.next server dns_port q_class q_type q_name

  let gethostbyname
      t ?(server = default_ns) ?(dns_port = default_port)
      ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_A)
      name =
    let domain = Name.of_string name in
    if is_local domain then
      Local.gethostbyname t.local ~server ~dns_port ~q_class ~q_type name
    else
      Next.gethostbyname t.next ~server ~dns_port ~q_class ~q_type name

  let gethostbyaddr
      t ?(server = default_ns) ?(dns_port = default_port)
      ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_PTR)
      addr =
    let domain = Name.of_ipaddr (Ipaddr.V4 addr) in
    if is_link_local domain then
      Local.gethostbyaddr t.local ~server ~dns_port ~q_class ~q_type addr
    else
      Next.gethostbyaddr t.next ~server ~dns_port ~q_class ~q_type addr
end

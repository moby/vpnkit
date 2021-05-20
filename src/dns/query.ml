(*
 * Copyright (c) 2005-2006 Tim Deegan <tjd@phlegethon.org>
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
 * dnsquery.ml -- map DNS query-response mechanism onto trie database
 *
 *)

(* We answer a query with RCODE, AA, ANSWERS, AUTHORITY and ADDITIONAL *)

type answer = {
  rcode : Packet.rcode;
  aa: bool;
  answer: Packet.rr list;
  authority: Packet.rr list;
  additional: Packet.rr list;
}

type filter = Name.t -> RR.rrset -> RR.rrset

type flush = Name.t -> Packet.rdata -> bool

let response_of_answer ?(mdns=false) query answer =
  (*let edns_rec =
    try
    List.find (fun rr -> ) query.additionals
    with Not_found -> []
    in *)
  let detail = {
    Packet.qr=Packet.Response; opcode=Packet.Standard; aa=answer.aa;
    tc=false;
    rd=(if mdns then false else Packet.(query.detail.rd));  (* rfc6762 s18.6_p1_c1 *)
    ra=false; rcode=answer.rcode
  } in
  Packet.({
      id=(if mdns then 0 else query.id);
      detail;
      (* mDNS does not echo questions in the response *)
      questions=(if mdns then [] else query.questions);
      answers=answer.answer;
      authorities=answer.authority;
      additionals=answer.additional;
    })

let answer_of_response ?(preserve_aa=false) ({
  Packet.detail={ Packet.rcode; aa; _ };
  answers; authorities; additionals; _
}) = { rcode; aa = if preserve_aa then aa else false;
       answer=answers;
       authority=authorities;
       additional=additionals;
     }

let create ?(dnssec=false) ~id q_class q_type q_name =
  let open Packet in
  let detail = {
    qr=Query; opcode=Standard;
    aa=false; tc=false; rd=true; ra=false; rcode=NoError;
  } in
  let additionals =
    if dnssec then
      [ ( {
        name=Name.empty; cls=RR_IN; flush=false; ttl=0l;
        rdata=(EDNS0(1500, 0, true, []));} ) ]
    else
      []
  in
  let question = { q_name; q_type; q_class; q_unicast=Q_Normal } in
  { id; detail; questions=[question];
    answers=[]; authorities=[]; additionals;
  }

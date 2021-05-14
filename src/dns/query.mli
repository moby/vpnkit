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
 *)

(**  Map DNS query-response mechanism onto trie database.

     @author Tim Deegan
     @author Richard Mortier <mort\@cantab.net> (documentation)
*)

(** Partially-marshalled query response; that is, it has been uncompacted from
    the compact {! Trie} representation, but not yet rendered into a {!
    Cstruct.buf }.
*)
type answer = {
  rcode : Packet.rcode;
  aa: bool;
  answer: Packet.rr list;
  authority: Packet.rr list;
  additional: Packet.rr list;
}

type filter = Name.t -> RR.rrset -> RR.rrset

type flush = Name.t -> Packet.rdata -> bool

(** [response_of_answer query answer] is the {! Packet.t } constructed
    from the [answer] to the [query]
*)
val response_of_answer : ?mdns:bool ->
  Packet.t -> answer -> Packet.t

(** [answer_of_response response] is the {! answer } corresponding
    to the upstream [response] for proxied or forwarded response.
*)
val answer_of_response : ?preserve_aa:bool -> Packet.t -> answer

(** Answer a query about {! domain_name}, given a query type {! q_type} and a
    {! Trie} of DNS data.

    @return the {! answer}
*)
val answer : ?dnssec:bool -> ?mdns:bool -> ?filter:filter -> ?flush:flush ->
  Name.t -> Packet.q_type -> Trie.dnstrie -> answer

(** Answer one or more {! questions} given a {! Trie} of DNS data.

    @return the {! answer}
*)
val answer_multiple : ?dnssec:bool -> ?mdns:bool -> ?filter:filter -> ?flush:flush ->
  Packet.question list -> Trie.dnstrie -> answer

(** [create ~id q_class q_type q_name] creates a query for [q_name] with the
    supplied [id], [q_class], and [q_type].
*)
val create : ?dnssec:bool -> id:int -> Packet.q_class -> Packet.q_type ->
             Name.t -> Packet.t

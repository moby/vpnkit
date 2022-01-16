(*
 * Copyright (C) 2016 David Scott <dave@recoil.org>
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

module Make(Time: Mirage_time.S): sig
  type t
  (** A cache of DNS answers *)

  val make: ?max_bindings:int -> unit -> t
  (** Create an empty cache. If [?max_bindings] is provided then the cache will
      not contain more than the given number of bindings. *)

  val destroy: t -> unit
  (** Destroy the cache and free associated resources *)

  val answer: t -> Dns_forward_config.Address.t -> Dns.Packet.question -> Dns.Packet.rr list option
  (** Look up the answer given by a specific server to a question. Returns
      None if no answer is cached from that server. *)

  val insert: t -> Dns_forward_config.Address.t -> Dns.Packet.question -> Dns.Packet.rr list -> unit
  (** Insert the answer to the question into the cache *)
end

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

val default_ns : Ipaddr.V4.t
val default_port : int

module type S = Dns_resolver_mirage.S

module Client : Dns.Protocol.CLIENT

(** Resolves queries using mDNS *)
module Make(TIME: Mirage_time_lwt.S)(S:Mirage_stack_lwt.V4) : S with type stack = S.t

(** Resolves queries for *.local and 169.254.x.x using Local
    (which is intended to be the result of [Make] above),
    and resolves any other names using the [Next] resolver *)
module Chain(Local:S)(Next:S with type stack = Local.stack) : S with type stack = Local.stack

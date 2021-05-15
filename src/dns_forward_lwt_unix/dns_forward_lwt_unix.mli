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

(** DNS utilities over Lwt_unix *)

module Resolver: sig
  module Udp: Dns_forward.Resolver.S
  (** A DNS resolver over UDP *)

  module Tcp: Dns_forward.Resolver.S
  (** A DNS resolver over TCP *)
end

module Server: sig
  module Udp: Dns_forward.Server.S with type resolver = Resolver.Udp.t
  (** A forwarding DNS proxy over UDP *)

  module Tcp: Dns_forward.Server.S with type resolver = Resolver.Tcp.t
  (** A forwarding DNS proxy over TCP *)
end

module Clock: Mirage_clock.MCLOCK

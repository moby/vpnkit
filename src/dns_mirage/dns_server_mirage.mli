(*
 * Copyright (c) 2015 Heidi Howard <hh360@cam.ac.uk>
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

open Dns_server

module type S = sig
  type t
  type stack
  type kv_ro

  val create : stack -> kv_ro -> t

  (** Generate a {! Dns.Packet.t process} from a {! list} of filenames
   corresponding to zone files. *)
  val eventual_process_of_zonefiles : t-> string list -> Dns.Packet.t process Lwt.t

  val serve_with_processor: t -> port:int -> processor:(module PROCESSOR) -> unit Lwt.t
 
  val serve_with_zonefile : t -> port:int -> zonefile:string -> unit Lwt.t

  val serve_with_zonefiles : t -> port:int -> zonefiles:string list -> unit Lwt.t

  val serve_with_zonebuf : t -> port:int -> zonebuf:string -> unit Lwt.t

  val serve_with_zonebufs : t -> port:int -> zonebufs:string list -> unit Lwt.t

end

module Make(K:Mirage_kv_lwt.RO)(Stack:Mirage_stack_lwt.V4) : sig
  include S with type stack = Stack.t and type kv_ro = K.t
end

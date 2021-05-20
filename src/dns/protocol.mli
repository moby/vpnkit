(*
 * Copyright (c) 2013 David Sheets <sheets@alum.mit.edu>
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

exception Dns_resolve_timeout
exception Dns_resolve_error of exn list

(** The type of pluggable DNS resolver modules for request contexts and
    custom metadata and wire protocols.
*)
module type CLIENT = sig
  type context

  val get_id : unit -> int

  (** [marshal query] is a list of context-buffer pairs corresponding to the
      channel contexts and request buffers with which to attempt DNS requests.
      Requests are made in parallel and the first response to successfully
      parse is returned as the answer. Lagging requests are kept running until
      successful parse or timeout. With this behavior, it is easy to construct
      low-latency but network-environment-aware DNS resolvers.
  *)
  val marshal : ?alloc:(unit -> Cstruct.t) -> Packet.t -> (context * Cstruct.t) list

  (** [parse ctxt buf] is the potential packet extracted out of [buf]
      with [ctxt]
  *)
  val parse : context -> Cstruct.t -> Packet.t option

  (** [timeout ctxt] is the exception resulting from a context [ctxt] that has
      timed-out
  *)
  val timeout : context -> exn
end

(** The default DNS resolver using the standard DNS protocol *)
module Client : CLIENT

(** The type of pluggable DNS server modules for request contexts and
    custom metadata dn wire protocols.
*)
module type SERVER = sig
  type context

  (** Projects a context into its associated query *)
  val query_of_context : context -> Packet.t

  (** DNS wire format parser function.
      @param buf message buffer
      @return parsed packet and context
  *)
  val parse   : Cstruct.t -> context option

  (** DNS wire format marshal function.
      @param alloc allocator
      @param _q context
      @param response answer packet
      @return buffer to write
  *)
  val marshal : ?alloc:(unit -> Cstruct.t) -> context -> Packet.t -> Cstruct.t option
end

(** The default DNS server using the standard DNS protocol *)
module Server : SERVER with type context = Packet.t

val contain_exc : string -> (unit -> 'a) -> 'a option

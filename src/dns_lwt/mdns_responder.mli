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

(** Multicast DNS (RFC 6762) Responder.

    This is roughly the mDNS equivalent of Dns_server,
    in that it accepts mDNS query packets
    and responds with the matching records from a zone file.

    The simplest usage is with shared resource records only,
    which requires the following steps:

    + Create a module from a zone buffer using the "Make" functor.
    + Call the module's "announce" function to announce the records.
    + After announcement completes, call the "process" function for
      each received packet.

    The use of unique resource records requires alternative steps:

    + Create a module from a zone buffer using the "Make" functor.
    + Call "add_unique_hostname" to add the a unique "A" record.
    + Call the module's "first_probe" function to probe for
      uniqueness of the hostname. The name will be changed to
      something unique in the event of a conflict.
    + After probing completes, call the module's "announce" function.
    + After announcement completes, call the "process" function for
      each received packet.

    As per RFC 6762 section 9, if at any time the responder observes a
    response that conflicts with a record that was previously
    already confirmed as unique, it restarts the probing sequence.
    Therefore, it is necessary to invoke the "stop_probe" function
    to shut down the responder.
*)

(** An endpoint address consisting of an IPv4 address and a UDP port number. *)
type ip_endpoint = Ipaddr.V4.t * int

(** Encapsulates the dependencies that the responder requires for performing I/O. *)
module type TRANSPORT = sig
  val alloc : unit -> Cstruct.t
  val write : ip_endpoint -> Cstruct.t -> unit Lwt.t
  val sleep : float -> unit Lwt.t
end

(** Creates an mDNS responder module given a module that provides I/O functions. *)
module Make : functor (Transport : TRANSPORT) -> sig
  (** The type of an mDNS responder instance. *)
  type t

  (** Creates a responder by parsing a list of zone buffer strings. *)
  val of_zonebufs : string list -> t

  (** Creates a responder by parsing a zone buffer string, which is typically loaded from a zone file. *)
  val of_zonebuf : string -> t

  (** Creates a responder from a previously loaded DNS database. *)
  val of_db : Dns.Loader.db -> t

  (** Adds an A resource record that is intended to be unique on the local link.
      The responder will only include this record in responses after
      it has been confirmed as unique by probing, which is initiated by
      calling "first_probe".
  *)
  val add_unique_hostname : t -> Dns.Name.t -> ?ttl:int32 -> Ipaddr.V4.t -> unit

  (** Initiates the first probe sequence to verify ownership of any unique records.
      If no unique records have been added then this function will do nothing.
  *)
  val first_probe : t -> unit Lwt.t

  (** Initiates the announcement sequence which sends unsolicited responses
      for confirmed unique records and for shared records.
  *)
  val announce : t -> repeat:int -> unit Lwt.t

  (** Processes a received mDNS UDP datagram.
      The main purpose of this function is to send responses to
      mDNS queries, but it also parses responses to detect
      conflicts with unique records.
  *)
  val process : t -> src:ip_endpoint -> dst:ip_endpoint -> Cstruct.t -> unit Lwt.t

  (** Call this function to permanently stop the probe thread,
      to shut down the responder.
  *)
  val stop_probe : t -> unit Lwt.t

  (** Returns the trie that the responder uses internally to store RRs. *)
  val trie : t -> Dns.Trie.dnstrie
end


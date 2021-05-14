(*
 * Copyright (c) 2011 Anil Madhavapeddy <anil@recoil.org>
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

(** The main purpose of this module is to provide an implementation of a
    standard DNS server based on {!Dns.Query} and {!Dns.Loader}.

    For a basic DNS server, call {!process_of_zonebuf}, pass
    the result to {!processor_of_process}, and then invoke
    the resulting processor function for each received packet.

    This module also provides a way to override the parsing and marshaling of
    DNS packets to allow extensions of DNS to be implemented, such as DNSCurve.
*)

(** A tuple consisting of an IPv4 or IPv6 address and a TCP or UDP port number. *)
type ip_endpoint = Ipaddr.t * int

(** A type of function that takes an abstract request plus source and destination
    endpoint addresses, and asynchronously produces an answer to the request,
    or None if no answer is possible. For most applications the type {!'a}
    will be {!Dns.Packet.t}, but may be different if a custom parsing/marshalling
    layer is required.
*)
type 'a process = src:ip_endpoint -> dst:ip_endpoint -> 'a -> Dns.Query.answer option Lwt.t

(** This type of module provides functions for parsing, marshalling and processing
    DNS requests to produce answers. *)
module type PROCESSOR = sig
  include Dns.Protocol.SERVER

  (** DNS responder function.
      Takes an abstract request plus source and destination
      endpoint addresses, and asynchronously produces an answer to the request,
      or None if no answer is possible. *)
  val process : context process
end

type 'a processor = (module PROCESSOR with type context = 'a)

(** [compose process backup_process] is [process] unless it returns 
	an {!rcode} other than {!NoError} in which case it becomes [backup_process]. *)
val compose: Dns.Packet.t process -> Dns.Packet.t process -> Dns.Packet.t process

(** [process_query ?alloc ibuf ibuflen src dst processor] *)
val process_query: ?alloc:(unit -> Cstruct.t) -> Cstruct.t -> int -> ip_endpoint -> ip_endpoint -> 
  (module PROCESSOR) -> Cstruct.t option Lwt.t

(** Returns a packet processor module by combining {!Dns.Protocol.Server} with
    the specified packet processing function. *)
val processor_of_process : Dns.Packet.t process -> Dns.Packet.t processor

(** Given a list of DNS zone files as strings, parses them
    using {!Dns.Loader} and returns a processing
    function that answers requests through the use of {!Dns.Query}. *)
val process_of_zonebufs : string list -> Dns.Packet.t process

(** This is a convenience function that is equivalent to calling
    {!process_of_zonebufs} with a list containing a single zone file string. *)
val process_of_zonebuf : string -> Dns.Packet.t process

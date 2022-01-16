(*
 * Copyright (c) 2014 Anil Madhavapeddy <anil@recoil.org>
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

module type S = sig
  type t
  type stack

  val create : stack -> t

  val resolve :
    (module Dns.Protocol.CLIENT) ->
    t -> Ipaddr.V4.t -> int ->
    Dns.Packet.q_class ->
    Dns.Packet.q_type ->
    Dns.Name.t ->
    Dns.Packet.t Lwt.t

  val gethostbyname : t ->
    ?server:Ipaddr.V4.t -> ?dns_port:int ->
    ?q_class:Dns.Packet.q_class ->
    ?q_type:Dns.Packet.q_type ->
    string -> Ipaddr.t list Lwt.t

  val gethostbyaddr : t ->
    ?server:Ipaddr.V4.t -> ?dns_port:int ->
    ?q_class:Dns.Packet.q_class ->
    ?q_type:Dns.Packet.q_type ->
    Ipaddr.V4.t -> string list Lwt.t
end

type static_dns = 
{
  names: (string, Ipaddr.t) Hashtbl.t;
  rev: (Ipaddr.V4.t, string) Hashtbl.t;
}

module Static : S with type stack = static_dns

module Make(Time:Mirage_time.S)(S:Mirage_stack.V4) : S with type stack = S.t

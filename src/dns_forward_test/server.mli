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
open Dns_forward

module Make(Server: Rpc.Server.S): sig
  type t
  (** A DNS server for testing *)

  val make: ?delay:float -> ?simulate_bad_question:bool -> (string * Ipaddr.t) list -> t
  (** Construct a server with a fixed set of name mappings. If the ?delay
      argument is provided then an artificial delay will be added before all
      responses. If ?simulate_bad_question is true then the responses will contain
      a bad question, as could happen if a packet with an old id turned up.*)

  type server
  (** A running server *)

  val serve: address: Config.Address.t -> t -> server Error.t
  (** Serve requests on the given IP and port forever *)

  val shutdown: server -> unit Lwt.t
  (** Shutdown the running server *)

  val get_nr_queries: t -> int
  (** Return the number of queries which reached this server *)

end

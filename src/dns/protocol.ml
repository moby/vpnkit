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

module type CLIENT = sig
  type context

  val get_id : unit -> int

  val marshal : ?alloc:(unit -> Cstruct.t) -> Packet.t -> (context * Cstruct.t) list
  val parse : context -> Cstruct.t -> Packet.t option

  val timeout : context -> exn
end

module Client : CLIENT = struct
  type context = int

  (* TODO: XXX FIXME SECURITY EXPLOIT HELP: random enough? *)
  let get_id () =
    Random.self_init ();
    Random.int (1 lsl 16)

  let marshal ?alloc q =
    [q.Packet.id, Packet.marshal ?alloc q]

  let parse id buf =
    let pkt = Packet.parse buf in
    if pkt.Packet.id = id then Some pkt else None

  let timeout _id = Dns_resolve_timeout
end

module type SERVER = sig
  type context

  val query_of_context : context -> Packet.t

  val parse   : Cstruct.t -> context option
  val marshal : ?alloc:(unit -> Cstruct.t) -> context -> Packet.t -> Cstruct.t option

end

let contain_exc l v =
  try
    Some (v ())
  with exn ->
    Printexc.print_backtrace stderr;
    Printf.eprintf "dns %s exn: %s\n%!" l (Printexc.to_string exn);
    None

module Server : SERVER with type context = Packet.t = struct
  type context = Packet.t

  let query_of_context x = x

  let parse buf = contain_exc "parse" (fun () -> Packet.parse buf)
  let marshal ?alloc _q response =
    contain_exc "marshal" (fun () -> Packet.marshal ?alloc response)
end

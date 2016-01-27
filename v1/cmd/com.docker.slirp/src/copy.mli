(*
 * Copyright (C) 2016 David Scott <dave.scott@docker.com>
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

type t
(** A copy operation *)

type stats = {
	read_bytes: int64;
	read_ops: int64;
	write_bytes: int64;
	write_ops: int64;
	duration: float;
}

val string_of_stats: stats -> string

val stats: t -> stats
(** [stats t] returns instantantaneous stats about a copy *)

val start:
     (module V1.CLOCK)
	-> (module V1_LWT.FLOW with type flow = 'a) -> 'a
	-> (module V1_LWT.FLOW with type flow = 'b) -> 'b
	-> unit -> t
(** [start (module Clock) (module Source) source (module Destination)
    destination] copies data from [source] to [destination] using the
		clock to compute a transfer rate. *)

val wait: t -> [ `Ok of unit | `Error of [ `Msg of string ] ] Lwt.t
(** [wait t] waits for the copy process to complete. The call succeeds iff all
    the data read from source (until Eof) is successfully written to destination. *)

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

(** Accept connections and talk to clients via the vmnetd protocol, exposing
    the packets as a Mirage NETWORK interface *)

include V1_LWT.NETWORK
  with type buffer = Cstruct.t

val add_listener: t -> (Cstruct.t -> unit Lwt.t) -> unit

val of_fd: client_macaddr:Macaddr.t -> server_macaddr:Macaddr.t -> Lwt_unix.file_descr -> [ `Ok of t | `Error of [ `Msg of string ] ] Lwt.t
(** [of_fd ~client_macaddr ~server_macaddr fd] negotiates with the client over
    [fd]. The client uses [client_macaddr] as the source address of all its ethernet
    frames. The server uses [server_macaddr] as the source address of all its
    ethernet frames. *)

val client_of_fd: client_macaddr:Macaddr.t -> server_macaddr:Macaddr.t -> Lwt_unix.file_descr -> [ `Ok of t | `Error of [ `Msg of string ] ] Lwt.t

val start_capture: t -> ?size_limit:int64 -> string -> unit Lwt.t
(** [start_capture t ?size_limit filename] closes any existing pcap capture
    file and starts capturing to [filename]. If [?size_limit] is provided
    then the file will be automatically closed after the given number of
    bytes are written -- this is to avoid forgetting to close the file and
    filling up your storage with capture data. *)

val stop_capture: t -> unit Lwt.t
(** [stop_capture t] stops any in-progress capture and closes the file. *)

module Init : sig
  type t

  val to_string: t -> string
  val sizeof: int
  val default: t

  val marshal: t -> Cstruct.t -> Cstruct.t
  val unmarshal: Cstruct.t -> [ `Ok of t * Cstruct.t  | `Error of [ `Msg of string ]]
end

module Command : sig

  type t =
    | Ethernet of string (* 36 bytes *)

    val to_string: t -> string
    val sizeof: int

    val marshal: t -> Cstruct.t -> Cstruct.t
    val unmarshal: Cstruct.t -> [ `Ok of t * Cstruct.t  | `Error of [ `Msg of string ]]
end

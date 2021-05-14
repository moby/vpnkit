(*
 * Copyright (c) 2011 Richard Mortier <mort@cantab.net>
 * Copyright (c) 2011 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2015 Heidi Howard <hh360@cam.ac.uk>
 * Copyright (c) 2015 David Sheets <sheets@alum.mit.edu>
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

(** Domain name and label handling.

    @author Tim Deegan
    @author Richard Mortier <mort\@cantab.net> (documentation)
*)

(** DNS label, including pointer and zero. *)
type label

(** Domain name, as a list of labels ordered from the leaf to the root. *)
type t

(** Lookup key for the {! Trie}. *)
type key = string

(** Domain name map *)
module Map: Map.S with type key = t

(** Domain name set *)
module Set: Set.S with type elt = t

(** [empty] is the empty {! t}. *)
val empty: t

(** [to_string_list name] is the label list corresponding to [name]. *)
val to_string_list : t -> string list

(** [of_string_list slist] is the domain name corresponding to label
    list [slist]. *)
val of_string_list : string list -> t

(** [append a b] is the domain name of the concatenation of [a] and [b]. *)
val append: t -> t -> t

(** [cons label name] is the domain name with subdomain [label] under [name]. *)
val cons: string -> t -> t

(** [to_string name] is the normal, human-readable string
    serialization of [name] without the trailing dot. *)
val to_string : t -> string

(** [of_string name] is the domain name parsed out of the normal,
    human-readable serialization [name]. *)
val of_string : string -> t

(** [string_to_domain_name] is {! of_string } but retained for
    backward compatibility.
    @deprecated since 0.15.0; use {! of_string } in new developments *)
val string_to_domain_name : string -> t

(** [of_ipaddr ip] is the name used for reverse lookup of IP address [ip]. *)
val of_ipaddr : Ipaddr.t -> t

(** Parse a {! t} out of a {! Cstruct.t} given a set of already
    observed names from the packet, and the offset we are into the packet.

    @return {! t} and the remainder
*)
val parse :
  (int, label) Hashtbl.t -> int -> Cstruct.t -> t * (int * Cstruct.t)

val marshal : ?compress:bool ->
  int Map.t -> int -> Cstruct.t -> t -> int Map.t * int * Cstruct.t

(** Construct a {! Hashcons} character-string from a string. *)
val hashcons_string : string -> string Hashcons.hash_consed

(** Construct a {! Hashcons} domain name (list of labels) from a {!
    t}. *)
val hashcons : t -> t Hashcons.hash_consed

(** Clear the {! Hashcons} tables. *)
val clear_cons_tables : unit -> unit

(** Malformed input to {! canon2key}. *)
exception BadDomainName of string

(** Convert a canonical [[ "www"; "example"; "com" ]] domain name into a key. *)
val to_key : t -> key

val dnssec_compare : t -> t -> int
val dnssec_compare_str : string list -> string list -> int

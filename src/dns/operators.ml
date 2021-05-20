(*
 * Copyright (c) 2012 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2011 Richard Mortier <mort@cantab.net>
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

(** Some widely used operators.

    @author Richard Mortier <mort\@cantab.net>
    @author Anil Madhavapeddy <anil\@recoil.org>
*)

(** Pipe. *)
external (|>) : 'a -> ('a -> 'b) -> 'b = "%revapply";;

(** Element-wise pipe. *)
let (||>) l f = List.map f l

(** 32 and 64 bit arithmetic and logic operations. *)

(** Addition. *)
let (+++) x y = Int32.add x y
let (++++) x y = Int64.add x y
(** Logical AND. *)
let (&&&) x y = Int32.logand x y
let (&&&&) x y = Int64.logand x y
(** Logical OR. *)
let (|||) x y = Int32.logor x y
let (||||) x y = Int64.logor x y
(** Logical XOR. *)
let (^^^) x y = Int32.logxor x y
let (^^^^) x y = Int64.logxor x y
(** Logical shift-left. *)
let (<|<) x y = Int32.shift_left x y
let (<||<) x y = Int64.shift_left x y
(** Logical shift-right. *)
let (>|>) x y = Int32.shift_right_logical x y
let (>||>) x y = Int64.shift_right_logical x y

(** Encode string as label by prepending length. *)
let charstr s =
  let n = String.length s in
  String.make 1 (char_of_int n) ^ s, (n+1)

(*
 * Copyright (c) 2012 Richard Mortier <mort@cantab.net>
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

(* open Wire *)
(* open Re_str *)

open Printf
open Operators

type t = string list

type key = string

module Ordered = struct
  type x = t
  type t = x
  let rec compare l1 l2 = match (l1, l2) with
    | []    ,  []    -> 0
    | _::_  , []     -> 1
    | []    , _::_   -> -1
    | h1::t1, h2::t2 ->
      match String.compare h1 h2 with
      | 0 -> compare t1 t2
      | i -> i
end

module Map = Map.Make(Ordered)
module Set = Set.Make(Ordered)

let empty = []
let append = (@)
let cons x xs = (String.lowercase_ascii x) :: xs
let to_string_list dn = dn
let of_string_list = List.map String.lowercase_ascii

let to_string = String.concat "."

(* TODO: this looks wrong for the trailing dot case/we should ensure
   we handle the trailing dot case consistently *)
let of_string (s:string) : t =
  Re.Str.split (Re.Str.regexp "\\.") (String.lowercase_ascii s)
let string_to_domain_name = of_string

let of_ipaddr ip = of_string_list @@ Domain_name.to_strings @@ Ipaddr.to_domain_name ip

type label =
  | L of string * int (* string *)
  | P of int * int (* pointer *)
  | Z of int (* zero; terminator *)

let parse_label base buf =
  (* NB. we're shifting buf for each call; offset is for the names Hashtbl *)
  match Cstruct.get_uint8 buf 0 with
    | 0 ->
        Z base, 1

    | v when ((v land 0b0_11000000) = 0b0_11000000) ->
        let ptr = ((v land 0b0_00111111) lsl 8) + Cstruct.get_uint8 buf 1 in
        P (ptr, base), 2

    | v ->
        if ((0 < v) && (v < 64)) then (
          let name = Cstruct.(sub buf 1 v |> to_string) in
          L (name, base), 1+v
        )
        else
          failwith (sprintf "Name.parse_label: invalid length %d" v)

let parse names base buf = (* what. a. mess. *)
  let rec aux offsets name base buf size =
    match parse_label base buf with
    | (Z o as zero, offset) ->
      Hashtbl.add names o zero;
      name, base+offset, Cstruct.shift buf offset, (size + 1)

    | (L (n, o) as label, offset) ->
      Hashtbl.add names o label;
      offsets |> List.iter (fun off -> (Hashtbl.add names off label));
      aux (o :: offsets) (n :: name) (base+offset) (Cstruct.shift buf offset) (size + offset)
      
    | (P (p, _), offset) ->
      (match Hashtbl.find_all names p with
       | [] -> failwith (sprintf "Name.parse_pointer: Cannot dereference pointer to (%n) at position (%n)" p base);
       | all ->
         let labels = (all |> List.filter (function L _ -> true | _ -> false)) in
         (* update the list of offsets-so-far to include current label *)
         (base :: offsets) |> List.iter (fun o ->
             (List.rev labels) |> List.iter (fun n -> Hashtbl.add names o n)
           );
         (* convert label list into string list *)
         let labels_str  = (labels ||> (function
             | L (nm,_) -> nm
             | _ -> failwith "Name.parse")
           )
         in
         let nb_labels = List.length labels_str in
         let label_size = List.fold_left (fun size str -> size + (String.length str)) nb_labels labels_str in
         labels_str@name, base+offset, Cstruct.shift buf offset, (size + label_size)
      )

  in
  let name, base, buf, size = aux [] [] base buf 0 in
  if size > 255 then
    failwith (sprintf "Name.parse: invalid length %d" size)
  else
    List.rev name, (base,buf)

let marshal ?(compress=true) names base buf name =
  let not_compressed names base buf name =
    let base, buf =
      List.fold_left (fun (base,buf) label ->
        let label,llen = charstr label in
        Cstruct.blit_from_string label 0 buf 0 llen;
        base+llen, Cstruct.shift buf llen
      ) (base, buf) name
    in names, base+1, Cstruct.shift buf 1
  in

  let compressed names base buf name =
    let pointer o = ((0b11_l <|< 14) +++ (Int32.of_int o)) |> Int32.to_int in

    let lookup names n =
      try Some (Map.find n names)
      with Not_found -> None
    in

    let rec aux names offset labels =
      match lookup names labels with
        | None ->
            (match labels with
              | [] ->
                  Cstruct.set_uint8 buf offset 0;
                  names, offset+1

              | (hd :: tl) as ls ->
                  let names = Map.add ls (base+offset) names in
                  let label, llen = charstr hd in
                  Cstruct.blit_from_string label 0 buf offset llen;
                  aux names (offset+llen) tl
            )

        | Some o ->
            Cstruct.BE.set_uint16 buf offset (pointer o);
            names, offset+2
    in
    let names, offset = aux names 0 name in
    names, (base+offset), Cstruct.shift buf offset
  in
  if compress then compressed names base buf name
  else not_compressed names base buf name

exception BadDomainName of string

let to_key domain_name =
  let check s =
    if String.contains s '\000' then
      raise (BadDomainName "contains null character");
    if String.length s = 0 then
      raise (BadDomainName "zero-length label");
    if String.length s > 63 then
      raise (BadDomainName ("label too long: " ^ s))
  in
  List.iter check domain_name;
  String.concat "\000" (List.rev_map String.lowercase_ascii domain_name)

let dnssec_compare a b =
  match (a, b) with
  | [], [] -> 0
  | [], _ -> -1
  | _, [] -> 1
  | a::a_tl, b::b_tl ->
      if (String.compare a b = 0) then
        compare a_tl b_tl
      else
        ( if (String.length a) = (String.length b) then
            String.compare a b
          else
            compare (String.length a) (String.length b)
        )
let dnssec_compare_str = dnssec_compare

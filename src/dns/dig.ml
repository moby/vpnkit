(*
 * Copyright (c) 2015 Heidi Howard <hh360@cam.ac.uk>
 * Copyright (c) 2005-2012 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2005 David Scott <djs@fraserresearch.org>
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

open Printf
open Packet

let al = List.length

let string_of_secname s = sprintf ";; %s SECTION:\n" (String.uppercase_ascii s)

let string_of_rr rr = sprintf "%-24s %-8lu %-8s %-8s %s\n"
  (Name.to_string rr.name) rr.ttl (rr_class_to_string rr.cls)

let string_of_rrecord rr = 
  match rr.rdata with
  |A ip -> string_of_rr rr "A" (Ipaddr.V4.to_string ip);
  |AAAA ip -> string_of_rr rr "AAAA" (Ipaddr.V6.to_string ip)
  |SOA (n1,n2,a1,a2,a3,a4,a5) ->
    string_of_rr rr "SOA"
      (sprintf "%s %s %lu %lu %lu %lu %lu" (Name.to_string n1)
        (Name.to_string n2) a1 a2 a3 a4 a5);
  |MX (pref,host) ->
    string_of_rr rr "MX" (sprintf "%d %s" pref (Name.to_string host));
  |CNAME a -> string_of_rr rr "CNAME" (Name.to_string a)
  |NS a -> string_of_rr rr "NS" (Name.to_string a)
  |TXT s -> string_of_rr rr "TXT" (sprintf "%S" (String.concat "" s))
  |_ -> "unknown\n"

let string_of_flags detail =  
  let if_flag a b = if a then None else Some b in
  let flags = [
      (match detail.qr with |Query -> None |Response -> Some "qr");
      (if_flag detail.aa "aa");
      (if_flag detail.tc "tc");
      (if_flag detail.rd "rd");
      (if_flag detail.ra "ra");
    ] in
  String.concat " " (List.fold_left (fun a -> function |None -> a |Some x -> x :: a) [] flags)

let string_of_question q = 
  sprintf ";%-23s %-8s %-8s %s\n"
    (Name.to_string q.q_name) ""
    (q_class_to_string q.q_class) (q_type_to_string q.q_type)

let string_of_section sfuc name rrs= 
  if al rrs > 0 then (
    List.fold_left (fun s q -> s ^ sfuc q) (string_of_secname name) rrs)
    ^ "\n"
  else ""

let string_of_answers p =
  let { detail; id; questions; answers; authorities; additionals } = p in
  String.concat "" 
  ([ ";; global options: \n";
    sprintf ";; ->>HEADER<<- opcode: %s, status: %s, id: %u\n"
      (String.uppercase_ascii (opcode_to_string detail.opcode))
      (String.uppercase_ascii (rcode_to_string detail.rcode)) id;
    sprintf ";; flags: %s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n\n"
      (string_of_flags detail) (al questions) (al answers) (al authorities) (al additionals);
    string_of_section string_of_question "question" questions;
  ] @
  List.map (fun (nm,ob) -> string_of_section string_of_rrecord nm ob)
    ["answer",answers; "authority",authorities; "additional",additionals])

(*
 * Copyright (c) 2005-2006 Tim Deegan <tjd@phlegethon.org>
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
 * dnsloader.ml -- how to build up a DNS trie from separate RRs
 *
 *)

open RR
open Trie
open Printf

(* Loader database: the DNS trie plus a hash table of other names in use *)
type db = {
    trie: dnstrie;		       	     (* Names that have RRSets *)
    mutable names: (Name.key, dnsnode) Hashtbl.t; (* All other names *)
  }

(* Get a new, empty database *)
let new_db () = { trie = new_trie ();
		  names = Hashtbl.create 101;
		}

(* Throw away the known names: call when guaranteed no more updates *)
let no_more_updates db = Hashtbl.clear db.names; db.names <- Hashtbl.create 1

(* Get the dnsnode that represents this name, making a new one if needed *)
let get_target_dnsnode owner db =
  let key = Name.to_key owner in
  match simple_lookup key db.trie with
    Some n -> n
  | None ->
      try
      	Hashtbl.find db.names key
      with Not_found ->
	let n = { owner = Name.hashcons owner;
		  rrsets = []; }
	in Hashtbl.add db.names key n ;
	n

(* Get the dnsnode that represents this name, making a new one if needed,
   inserting it into the trie, and returning both trie node and dnsnode *)
let get_owner_dnsnode owner db =
  let pull_name tbl key owner () =
    try
      match Hashtbl.find tbl key with
	d -> Hashtbl.remove tbl key; d
    with Not_found -> { owner = Name.hashcons owner;
			rrsets = []; }
  in
  let key = Name.to_key owner in
  lookup_or_insert key db.trie (pull_name db.names key owner)


(* How to add each type of RR to the database... *)
exception TTLMismatch

let add_rrset rrset owner db =
(* Merge a new RRSet into a list of RRSets. Returns the new list and the
   ttl of the resulting RRset. Reverses the order of the RRsets in the
   list *)
  let merge_rrset new_rrset rrsets =
    let cfn a b = compare (Hashtbl.hash a) (Hashtbl.hash b) in
    let mfn n o = List.merge cfn (List.fast_sort cfn n) o in
    let rec do_merge new_ttl new_rdata rrsets_done rrsets_rest =
      match rrsets_rest with
        | [] -> (new_ttl, { ttl = new_ttl; rdata = new_rdata } :: rrsets_done )
        | rrset :: rest -> match (new_rdata, rrset.rdata) with
            (A l1, A l2) ->
              (rrset.ttl, List.rev_append rest
                ({ ttl = rrset.ttl; rdata = A (mfn l1 l2) } :: rrsets_done))
            | (NS l1, NS l2) ->
                (rrset.ttl, List.rev_append rest
                  ({ ttl = rrset.ttl; rdata = NS (mfn l1 l2) } :: rrsets_done))
            | (CNAME l1, CNAME l2) ->
                (rrset.ttl, List.rev_append rest
                  ({ ttl = rrset.ttl; rdata = CNAME (mfn l1 l2) } :: rrsets_done))
            | (SOA l1, SOA l2) ->
                (rrset.ttl, List.rev_append rest
                  ({ ttl = rrset.ttl; rdata = SOA (mfn l1 l2) } :: rrsets_done))
            | (MB l1, MB l2) ->
                (rrset.ttl, List.rev_append rest
                  ({ ttl = rrset.ttl; rdata = MB (mfn l1 l2) } :: rrsets_done))
            | (MG l1, MG l2) ->
                (rrset.ttl, List.rev_append rest
                  ({ ttl = rrset.ttl; rdata = MG (mfn l1 l2) } :: rrsets_done))
            | (MR l1, MR l2) ->
                (rrset.ttl, List.rev_append rest
                  ({ ttl = rrset.ttl; rdata = MR (mfn l1 l2) } :: rrsets_done))
            | (WKS l1, WKS l2) ->
                (rrset.ttl, List.rev_append rest
                  ({ ttl = rrset.ttl; rdata = WKS (mfn l1 l2) } :: rrsets_done))
            | (PTR l1, PTR l2) ->
                (rrset.ttl, List.rev_append rest
                  ({ ttl = rrset.ttl; rdata = PTR (mfn l1 l2) } :: rrsets_done))
            | (HINFO l1, HINFO l2) ->
                (rrset.ttl, List.rev_append rest
                  ({ ttl = rrset.ttl; rdata = HINFO (mfn l1 l2) } :: rrsets_done))
            | (MINFO l1, MINFO l2) ->
                (rrset.ttl, List.rev_append rest
                  ({ ttl = rrset.ttl; rdata = MINFO (mfn l1 l2) } :: rrsets_done))
            | (MX l1, MX l2) ->
                (rrset.ttl, List.rev_append rest
                  ({ ttl = rrset.ttl; rdata = MX (mfn l1 l2) } :: rrsets_done))
            | (TXT l1, TXT l2) ->
                (rrset.ttl, List.rev_append rest
                  ({ ttl = rrset.ttl; rdata = TXT (mfn l1 l2) } :: rrsets_done))
            | (RP l1, RP l2) ->
                (rrset.ttl, List.rev_append rest
                  ({ ttl = rrset.ttl; rdata = RP (mfn l1 l2) } :: rrsets_done))
            | (AFSDB l1, AFSDB l2) ->
                (rrset.ttl, List.rev_append rest
                  ({ ttl = rrset.ttl; rdata = AFSDB (mfn l1 l2) } :: rrsets_done))
            | (X25 l1, X25 l2) ->
                (rrset.ttl, List.rev_append rest
                  ({ ttl = rrset.ttl; rdata = X25 (mfn l1 l2) } :: rrsets_done))
            | (ISDN l1, ISDN l2) ->
                (rrset.ttl, List.rev_append rest
                  ({ ttl = rrset.ttl; rdata = ISDN (mfn l1 l2) } :: rrsets_done))
            | (RT l1, RT l2) ->
                (rrset.ttl, List.rev_append rest
                  ({ ttl = rrset.ttl; rdata = RT (mfn l1 l2) } :: rrsets_done))
            | (AAAA l1, AAAA l2) ->
                (rrset.ttl, List.rev_append rest
                  ({ ttl = rrset.ttl; rdata = AAAA (mfn l1 l2) } :: rrsets_done))
            | (SRV l1, SRV l2) ->
                (rrset.ttl, List.rev_append rest
                  ({ ttl = rrset.ttl; rdata = SRV (mfn l1 l2) } :: rrsets_done))
            (* | (UNSPEC l1, UNSPEC l2) -> *)
            (*     (rrset.ttl, List.rev_append rest *)
            (*       ({ ttl = rrset.ttl; rdata = UNSPEC (mfn l1 l2) } :: rrsets_done)) *)
            | (DNSKEY l1, DNSKEY l2) ->
                (rrset.ttl, List.rev_append rest
                  ({ ttl = rrset.ttl; rdata = DNSKEY (mfn l1 l2) } :: rrsets_done))
            | (DS l1, DS l2) ->
                (rrset.ttl, List.rev_append rest
                  ({ ttl = rrset.ttl; rdata = DS (mfn l1 l2) } :: rrsets_done))
             | (Unknown (t1, l1), Unknown (t2, l2)) ->
                if t1 = t2 then
                  (rrset.ttl, List.rev_append rest
                    ({ ttl = rrset.ttl; rdata = Unknown (t1,(mfn l1 l2)) }
                     :: rrsets_done))
                else
                  do_merge new_ttl new_rdata (rrset :: rrsets_done) rest
            | (_, _) -> do_merge new_ttl new_rdata (rrset :: rrsets_done) rest
    in
    do_merge new_rrset.ttl new_rrset.rdata [] rrsets
  in
  let ownernode = get_owner_dnsnode owner db in
  let (old_ttl, new_rrsets) = merge_rrset rrset ownernode.rrsets in
  ownernode.rrsets <- new_rrsets;
  if not (old_ttl = rrset.ttl) then raise TTLMismatch

let add_generic_rr tcode str ttl owner db =
  let s = Name.hashcons_string str in
  add_rrset { ttl; rdata = Unknown (tcode, [ s ]) } owner db

let add_a_rr ip ttl owner db =
  add_rrset { ttl; rdata = A [ ip ] } owner db

let add_aaaa_rr ip ttl owner db =
  add_rrset { ttl; rdata = AAAA [ ip ] } owner db

let add_ns_rr target ttl owner db =
  try
    let targetnode = get_target_dnsnode target db in
    add_rrset { ttl; rdata = NS [ targetnode ] } owner db;
    fix_flags (Name.to_key owner) db.trie
  with TTLMismatch ->
    fix_flags (Name.to_key owner) db.trie; raise TTLMismatch

let add_cname_rr target ttl owner db =
  let targetnode = get_target_dnsnode target db in
  add_rrset { ttl; rdata = CNAME [ targetnode ] } owner db

let add_soa_rr master rp serial refresh retry expiry min ttl owner db =
  try
    let masternode = get_target_dnsnode master db in
    let rpnode = get_target_dnsnode rp db in
    let rdata = (masternode, rpnode, serial, refresh, retry, expiry, min) in
    add_rrset { ttl; rdata = SOA [ rdata ] } owner db;
    fix_flags (Name.to_key owner) db.trie
  with TTLMismatch ->
    fix_flags (Name.to_key owner) db.trie; raise TTLMismatch

let add_mb_rr target ttl owner db =
  let targetnode = get_target_dnsnode target db in
  add_rrset { ttl; rdata = MB [ targetnode ] } owner db

let add_mg_rr target ttl owner db =
  let targetnode = get_target_dnsnode target db in
  add_rrset { ttl; rdata = MG [ targetnode ] } owner db

let add_mr_rr target ttl owner db =
  let targetnode = get_target_dnsnode target db in
  add_rrset { ttl; rdata = MR [ targetnode ] } owner db

let add_wks_rr addr prot bitmap ttl owner db =
  let b = Name.hashcons_string bitmap in
  add_rrset { ttl; rdata = WKS [ (addr, prot, b) ] } owner db

let add_ptr_rr target ttl owner db =
  let targetnode = get_target_dnsnode target db in
  add_rrset { ttl; rdata = PTR [ targetnode ] } owner db

let add_hinfo_rr cpu os ttl owner db =
  let c = Name.hashcons_string cpu in
  let o = Name.hashcons_string os in
  add_rrset { ttl; rdata = HINFO [ (c, o) ] } owner db

let add_minfo_rr rmailbx emailbx ttl owner db =
  let rtarget = get_target_dnsnode rmailbx db in
  let etarget = get_target_dnsnode emailbx db in
  add_rrset { ttl; rdata = MINFO [ (rtarget, etarget) ] } owner db

let add_mx_rr pri target ttl owner db =
  let pri = pri in
  let targetnode = get_target_dnsnode target db in
  add_rrset { ttl; rdata = MX [ (pri, targetnode) ] } owner db

let add_txt_rr strl ttl owner db =
  let sl = List.map Name.hashcons_string strl in
  add_rrset { ttl; rdata = TXT [ sl ] } owner db

let add_rp_rr mbox txt ttl owner db =
  let mtarget = get_target_dnsnode mbox db in
  let ttarget = get_target_dnsnode txt db in
  add_rrset { ttl; rdata = RP [ (mtarget, ttarget) ] } owner db

let add_afsdb_rr subtype target ttl owner db =
  let st = subtype in
  let targetnode = get_target_dnsnode target db in
  add_rrset { ttl; rdata = AFSDB [ (st, targetnode) ] } owner db

let add_x25_rr addr ttl owner db =
  let a = Name.hashcons_string addr in
  add_rrset { ttl; rdata = X25 [ a ] } owner db

let add_isdn_rr addr sa ttl owner db =
  let a = Name.hashcons_string addr in
  let s = match sa with
    | None -> None
    | Some x -> Some (Name.hashcons_string x) in
  add_rrset { ttl; rdata = ISDN [ (a, s) ] } owner db

let add_rt_rr pref target ttl owner db =
  let pref = pref in
  let targetnode = get_target_dnsnode target db in
  add_rrset { ttl; rdata = RT [ (pref, targetnode) ] } owner db

let add_srv_rr pri weight port target ttl owner db =
  let pri = pri in
  let weight = weight in
  let port = port in
  let targetnode = get_target_dnsnode target db in
  add_rrset { ttl;
	      rdata = SRV [ (pri, weight, port, targetnode) ] } owner db

(* let add_unspec_rr str ttl owner db = *)
(*   let s = hashcons_charstring str in  *)
(*   add_rrset { ttl; rdata = UNSPEC [ s ] } owner db *)

let add_dnskey_rr flags typ key ttl owner db =
  let flags = flags in
  let typ = typ in
  let tmp = Base64.decode_exn key in
  let dnskey = Name.hashcons_string tmp in
  add_rrset { ttl; rdata = DNSKEY [ (flags, typ, dnskey) ] } owner db

(** valeur entière d'un chiffre hexa *)
let char_of_hex_value c =
  int_of_char c - (
    if c >= '0' && c <= '9' then 48 (*int_of_char '0'*)
              else if c >= 'A' && c <= 'F' then 55 (* int_of_char 'A' - 10 *)
    else if c >= 'a' && c <= 'f' then 87 (* int_of_char 'a' - 10
                  *)
              else assert false
  )

let init n f =
  if n >= 0
  then
    let s = Bytes.create n in
    for i = 0 to pred n do
      Bytes.set s i (f i)
    done ;
    s
    else
      let n = (- n) in
      let s = Bytes.create n in
      for i = pred n downto 0 do
        Bytes.set s i (f (n-i-1))
    done ;
    s

let string_of_hex s =
  let l = String.length s in
  if l land 1 = 1 then invalid_arg "Bytes.from_hex" ;
        init (l lsr 1) (
          fun i ->
            let i = i lsl 1 in
            Char.chr (
              (char_of_hex_value (String.get s i) lsl 4)
              + (char_of_hex_value (String.get s (i+1)))
            )
       ) |> Bytes.to_string


let add_ds_rr tag alg digest key ttl owner db =
  let alg =
    match (Packet.int_to_dnssec_alg alg) with
      | None -> failwith (sprintf "add_ds_rr: unsupported alg id %d" alg)
      | Some a -> a
  in
  let digest =
    match (Packet.int_to_digest_alg digest) with
      | Some a -> a
      | None -> failwith (sprintf "add_ds_rr : invalid hashing alg %d" digest)
  in
  let tmp = string_of_hex key in
  let ds = Name.hashcons_string tmp in
  add_rrset { ttl; rdata = DS [ (tag, alg, digest, ds) ] } owner db

let add_rrsig_rr typ alg lbl orig_ttl exp_ts inc_ts tag name sign ttl owner db =
  let typ =
    match (Packet.string_to_rr_type ("RR_"^typ)) with
      | None -> failwith (sprintf "add_rrsig_rr failed: uknown type %s" typ)
      | Some a -> a
            in
  let alg =
    match (Packet.int_to_dnssec_alg alg) with
      | None -> failwith (sprintf "add_rrsig_rr failed: uknown dnssec alg %d" alg)
      | Some a -> a
  in
    (* TODO: Check if sign is in the future or if the sign has expired *)
  let sign = Base64.decode_exn sign in
  let rr = RRSIG [{
    rrsig_type   = typ;
    rrsig_alg    = alg;
    rrsig_labels = char_of_int lbl;
    rrsig_ttl    = orig_ttl;
    rrsig_expiry = exp_ts;
    rrsig_incept = inc_ts;
    rrsig_keytag = tag;
    rrsig_name   = name;
    rrsig_sig    = sign;
  }] in
  add_rrset { ttl; rdata = rr; } owner db

  (* State variables for the parser & lexer *)
type parserstate = {
  mutable db: db;
  mutable paren: int;
  mutable filename: string;
  mutable lineno: int;
  mutable origin: Name.t;
  mutable ttl: int32;
  mutable owner: Name.t;
}

let new_state () = {
  db = new_db ();
  paren = 0;
  filename = "";
  lineno = 1;
  ttl = Int32.of_int 3600;
  origin = Name.empty;
  owner = Name.empty;
}

let state = new_state ()

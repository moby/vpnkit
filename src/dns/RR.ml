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
 * dnsrr.ml --- datatypes and handling for DNS RRs and RRSets
 *
 *)

(* Mnemonicity! *)
type serial = int32
type cstr = string Hashcons.hash_consed

(* DNS node: everything we know about a domain name *)
and dnsnode = {
  owner: Name.t Hashcons.hash_consed;
  mutable rrsets: rrset list;
}

(* RRSet: TTL, type, and some number of rdata *)
and rrset = {
  ttl: int32;
  rdata: rdata;
}

and rrsig = {
  rrsig_type   : Packet.rr_type;
  rrsig_alg    : Packet.dnssec_alg;
  rrsig_labels : char;
  rrsig_ttl    : int32;
  rrsig_expiry : int32;
  rrsig_incept : int32;
  rrsig_keytag : int;
  rrsig_name   : Name.t;
  rrsig_sig    : string;
}

and rdata =
  | A of Ipaddr.V4.t list (* always length = 1 *)
  | AAAA of Ipaddr.V6.t list (* always length = 1 *)
  | AFSDB of (Cstruct.uint16 * dnsnode) list
  | CNAME of dnsnode list
  | HINFO of (cstr * cstr) list
  | ISDN of (cstr * cstr option) list
  | MB of dnsnode list
  (* MD and MF are obsolete; use MX for them *)
  | MG of dnsnode list
  | MINFO of (dnsnode * dnsnode) list
  | MR of dnsnode list
  | MX of (Cstruct.uint16 * dnsnode) list
  | NS of dnsnode list
  | PTR of dnsnode list
  | RP of (dnsnode * dnsnode) list
  | RT of (Cstruct.uint16 * dnsnode) list
  | SOA of (dnsnode * dnsnode * serial * int32 * int32 * int32 * int32) list
  | SRV of (Cstruct.uint16 * Cstruct.uint16 * Cstruct.uint16 * dnsnode) list
  | TXT of (cstr list) list
  (* | UNSPEC of cstr list*)
  | Unknown of int * cstr list
  | WKS of (Ipaddr.V4.t * Cstruct.byte * cstr) list
  | X25 of cstr list
  | DNSKEY of (int * int * cstr) list
  | DS of (int * Packet.dnssec_alg * Packet.digest_alg * cstr) list
  | RRSIG of rrsig list

(* XXX add other RR types *)
(* wire-domain type for non-rfc1035 rdata? *)

let rdata_to_string = function
  | A _ -> "A"
  | AAAA _ -> "AAAA"
  | AFSDB _ -> "AFSDB"
  | CNAME _ -> "CNAME"
  | HINFO _ -> "HINFO"
  | ISDN _ -> "ISDN"
  | MB _ -> "MB"
  | MG _ -> "MG"
  | MINFO _ -> "MINFO"
  | MR _ -> "MR"
  | MX _ -> "MX"
  | NS _ -> "NS"
  | PTR _ -> "PTR"
  | RP _ -> "RP"
  | RT _ -> "RT"
  | SOA _ -> "SOA"
  | SRV _ -> "SRV"
  | TXT _ -> "TXT"
  | Unknown _ -> "Unknown"
  | WKS _ -> "WKS"
  | X25 _ -> "X25"
  | DNSKEY _ -> "DNSKEY"
  | RRSIG _ -> "RRSIG"
  | DS _ -> "DS"

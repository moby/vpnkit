(*
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

(* RFC1035, RFC1186 *)

[@@@ ocaml.warning "-32-37"]

open Printf
open Operators


[%%cenum
type digest_alg =
  | SHA1   [@id 1]
  | SHA256 [@id 2]
  [@@uint8_t]
]

[%%cenum
type gateway_tc =
  | NONE  [@id 0]
  | IPv4  [@id 1]
  | IPv6  [@id 2]
  | NAME  [@id 3]
  [@@ uint8_t]
]

type gateway =
  | IPv4 of Ipaddr.V4.t
  | IPv6 of Ipaddr.V6.t
  | NAME of Name.t
let gateway_to_string = function
  | IPv4 i -> Ipaddr.V4.to_string i
  | IPv6 i -> Ipaddr.V6.to_string i
  | NAME n -> Name.to_string n

[%%cenum
type pubkey_alg =
  | RESERVED [@id 0]
  | RSA      [@id 1]
  | DSS      [@id 2]
  [@@uint8_t]
]

[%%cenum
type ipseckey_alg =
  | DSA  [@id 1]
  | RSA  [@id 2]
  [@@uint8_t]
]

[%%cenum
type hash_alg =
  | SHA1 [@id 1]
  [@@uint8_t]
]

[%%cenum
type fp_type =
  | SHA1 [@id 1]
  [@@uint8_t]
]

[%%cenum
type dnssec_alg =
  | RSAMD5     [@id 1]
  | DH         [@id 2]
  | DSA        [@id 3]
  | ECC        [@id 4]
  | RSASHA1    [@id 5]
  | RSANSEC3   [@id 7]
  | RSASHA256  [@id 8]
  | RSASHA512  [@id 10]
  | INDIRECT   [@id 252]
  | PRIVATEDNS [@id 253]
  | PRIVATEOID [@id 254]
  [@@uint8_t]
]

[%%cenum
type rr_type =
  | RR_UNUSED     [@id 0]
  | RR_A          [@id 1]
  | RR_NS         [@id 2]
  | RR_MD         [@id 3]
  | RR_MF         [@id 4]
  | RR_CNAME      [@id 5]
  | RR_SOA        [@id 6]
  | RR_MB         [@id 7]
  | RR_MG         [@id 8]
  | RR_MR         [@id 9]
  | RR_NULL       [@id 10]
  | RR_WKS        [@id 11]
  | RR_PTR        [@id 12]
  | RR_HINFO      [@id 13]
  | RR_MINFO      [@id 14]
  | RR_MX         [@id 15]
  | RR_TXT        [@id 16]
  | RR_RP         [@id 17]
  | RR_AFSDB      [@id 18]
  | RR_X25        [@id 19]
  | RR_ISDN       [@id 20]
  | RR_RT         [@id 21]
  | RR_NSAP       [@id 22]
  | RR_NSAPPTR    [@id 23]
  | RR_SIG        [@id 24]
  | RR_KEY        [@id 25]
  | RR_PX         [@id 26]
  | RR_GPOS       [@id 27]
  | RR_AAAA       [@id 28]
  | RR_LOC        [@id 29]
  | RR_NXT        [@id 30]
  | RR_EID        [@id 31]
  | RR_NIMLOC     [@id 32]
  | RR_SRV        [@id 33]
  | RR_ATMA       [@id 34]
  | RR_NAPTR      [@id 35]
  | RR_KM         [@id 36]
  | RR_CERT       [@id 37]
  | RR_A6         [@id 38]
  | RR_DNAME      [@id 39]
  | RR_SINK       [@id 40]
  | RR_OPT        [@id 41]
  | RR_APL        [@id 42]
  | RR_DS         [@id 43]
  | RR_SSHFP      [@id 44]
  | RR_IPSECKEY   [@id 45]
  | RR_RRSIG      [@id 46]
  | RR_NSEC       [@id 47]
  | RR_DNSKEY     [@id 48]
  | RR_NSEC3      [@id 50]
  | RR_NSEC3PARAM [@id 51]
  | RR_SPF        [@id 99]
  | RR_UINFO      [@id 100]
  | RR_UID        [@id 101]
  | RR_GID        [@id 102]
  | RR_UNSPEC     [@id 103]
  [@@uint8_t]
]

(*
   The Type Bit Maps field identifies the RRset types that exist at the
   NSEC RR's owner name.

   The RR type space is split into 256 window blocks, each representing
   the low-order 8 bits of the 16-bit RR type space.  Each block that
   has at least one active RR type is encoded using a single octet
   window number (from 0 to 255), a single octet bitmap length (from 1
   to 32) indicating the number of octets used for the window block's
   bitmap, and up to 32 octets (256 bits) of bitmap.

   Blocks are present in the NSEC RR RDATA in increasing numerical
   order.

      Type Bit Maps Field = ( Window Block # | Bitmap Length | Bitmap )+

      where "|" denotes concatenation.

   Each bitmap encodes the low-order 8 bits of RR types within the
   window block, in network bit order.  The first bit is bit 0.  For
   window block 0, bit 1 corresponds to RR type 1 (A), bit 2 corresponds
   to RR type 2 (NS), and so forth.  For window block 1, bit 1
   corresponds to RR type 257, and bit 2 to RR type 258.  If a bit is
   set, it indicates that an RRset of that type is present for the NSEC
   RR's owner name.  If a bit is clear, it indicates that no RRset of
   that type is present for the NSEC RR's owner name.

   Bits representing pseudo-types MUST be clear, as they do not appear
   in zone data.  If encountered, they MUST be ignored upon being read.

   Blocks with no types present MUST NOT be included.  Trailing zero
   octets in the bitmap MUST be omitted.  The length of each block's
   bitmap is determined by the type code with the largest numerical
   value, within that block, among the set of RR types present at the
   NSEC RR's owner name.  Trailing zero octets not specified MUST be
   interpreted as zero octets.

   The bitmap for the NSEC RR at a delegation point requires special
   attention.  Bits corresponding to the delegation NS RRset and the RR
   types for which the parent zone has authoritative data MUST be set;
   bits corresponding to any non-NS RRset for which the parent is not
   authoritative MUST be clear.

   A zone MUST NOT include an NSEC RR for any domain name that only
   holds glue records.
*)
type type_bit_map = Cstruct.byte * Cstruct.byte * Cstruct.t
let type_bit_map_to_string (_tbm:type_bit_map) : string =
  "TYPE_BIT_MAP"

type type_bit_maps = type_bit_map list
let type_bit_maps_to_string (tbms:type_bit_maps) : string =
  tbms ||> type_bit_map_to_string |> String.concat "; "

type rdata =
  | A of Ipaddr.V4.t
  | AAAA of Ipaddr.V6.t
  | AFSDB of Cstruct.uint16 * Name.t
  | CNAME of Name.t
  | DNSKEY of Cstruct.uint16 * dnssec_alg * string
  | DS of Cstruct.uint16 * dnssec_alg * digest_alg * string
  | HINFO of string * string
  | IPSECKEY of Cstruct.byte * gateway_tc * ipseckey_alg * gateway * string
  | ISDN of string * string option
  | MB of Name.t
  | MD of Name.t
  | MF of Name.t
  | MG of Name.t
  | MINFO of Name.t * Name.t
  | MR of Name.t
  | MX of Cstruct.uint16 * Name.t
  | NS of Name.t
  | NSEC of Name.t (* uncompressed *) * type_bit_maps
  | NSEC3 of hash_alg * Cstruct.byte * Cstruct.uint16 * Cstruct.byte * string * Cstruct.byte * string *
      type_bit_maps
  | NSEC3PARAM of hash_alg * Cstruct.byte * Cstruct.uint16 * Cstruct.byte * string
  | PTR of Name.t
  | RP of Name.t * Name.t
  | RRSIG of rr_type * dnssec_alg * Cstruct.byte * int32 * int32 * int32 * Cstruct.uint16 *
      Name.t (* uncompressed *) * string
  | SIG of dnssec_alg * int32 * int32 * Cstruct.uint16 * Name.t * string
   | RT of Cstruct.uint16 * Name.t
  | SOA of Name.t * Name.t * int32 * int32 * int32 * int32 * int32
  | SRV of Cstruct.uint16 * Cstruct.uint16 * Cstruct.uint16 * Name.t
  | SSHFP of pubkey_alg * fp_type * string
  | TXT of string list
  | UNKNOWN of int * string
  (*  | UNSPEC of string -- wikipedia says deprecated in the 90s *)
  | WKS of Ipaddr.V4.t * Cstruct.byte * string
  | X25 of string
  | EDNS0 of (int * int * bool * ((int * string) list))

let hex_of_string in_str =
  let out_str = ref "" in
  let _ = String.iter (
    fun ch ->
      out_str := !out_str ^ (sprintf "%02x" (int_of_char ch))
  ) in_str in
    !out_str

let rdata_to_string = function
  | A ip -> sprintf "A (%s)" (Ipaddr.V4.to_string ip)
  | AAAA ip -> sprintf "AAAA (%s)" (Ipaddr.V6.to_string ip)
  | AFSDB (x, n)
    -> sprintf "AFSDB (%d, %s)" x (Name.to_string n)
  | CNAME n -> sprintf "CNAME (%s)" (Name.to_string n)
  | DNSKEY (flags, alg, key)
    -> (sprintf "DNSKEY (%d, %s, %s)"
          flags (dnssec_alg_to_string alg)
          (Base64.encode_exn key)
    )
  | HINFO (cpu, os) -> sprintf "HINFO (%s, %s)" cpu os
  | ISDN (a, sa)
    -> sprintf "ISDN (%s, %s)" a (match sa with None -> "" | Some sa -> sa)
  | MB n -> sprintf "MB (%s)" (Name.to_string n)
  | MD n -> sprintf "MD (%s)" (Name.to_string n)
  | MF n -> sprintf "MF (%s)" (Name.to_string n)
  | MG n -> sprintf "MG (%s)" (Name.to_string n)
  | MINFO (rm, em)
    -> (sprintf "MINFO (%s, %s)"
          (Name.to_string rm) (Name.to_string em)
    )
  | MR n -> sprintf "MR (%s)" (Name.to_string n)
  | MX (pref, name)
    -> sprintf "MX (%d, %s)" pref (Name.to_string name)
  | NS n -> sprintf "NS (%s)" (Name.to_string n)
  | PTR n -> sprintf "PTR (%s)" (Name.to_string n)
  | RP (mn, nn)
    -> (sprintf "RP (%s, %s)"
          (Name.to_string mn) (Name.to_string nn)
    )
  | RT (x, n)
    -> sprintf "RT (%d, %s)" x (Name.to_string n)
  | SOA (mn, rn, serial, refresh, retry, expire, minimum)
    -> (sprintf "SOA (%s,%s, %ld,%ld,%ld,%ld,%ld)"
          (Name.to_string mn) (Name.to_string rn)
          serial refresh retry expire minimum
    )
  | SRV (x, y, z, n)
    -> sprintf "SRV (%d,%d,%d, %s)" x y z (Name.to_string n)
  | TXT sl -> sprintf "TXT (%s)" (String.concat "" sl)
  | UNKNOWN (x, bs) -> sprintf "UNKNOWN (%d) '%s'" x (Base64.encode_exn bs)
  (* | UNSPEC bs -> sprintf "UNSPEC (%s)" bs*)
  | WKS (a, y, s) ->
    sprintf "WKS (%s, %d, %s)" (Ipaddr.V4.to_string a) (Cstruct.byte_to_int y) s
  | X25 s -> sprintf "X25 (%s)" s
  | EDNS0 (len, _rcode, do_bit, _opts) ->
      sprintf "EDNS0 (version:0, UDP: %d, flags: %s)"
        len (if (do_bit) then "do" else "")
  | RRSIG  (typ, alg, lbl, orig_ttl, exp_ts, inc_ts, tag, name, sign) ->
      sprintf "RRSIG (%s %s %d %ld %ld %ld %d %s %s)"
        (rr_type_to_string typ)
        (dnssec_alg_to_string alg) (int_of_char lbl) orig_ttl exp_ts inc_ts
        tag (Name.to_string name) (Base64.encode_exn sign)
  | SIG  (alg, exp_ts, inc_ts, tag, name, sign) ->
      sprintf "SIG (UNUSED %s 0 0 %ld %ld %d %s %s)"
        (dnssec_alg_to_string alg) exp_ts inc_ts
        tag (Name.to_string name) (Base64.encode_exn sign)
   | DS (keytag, alg, digest_t, digest)
    -> (sprintf "DS (%d,%s,%s, '%s')" keytag
          (dnssec_alg_to_string alg) (digest_alg_to_string digest_t)
          (hex_of_string digest)
    )
  | IPSECKEY (precedence, gw_type, alg, gw, pubkey)
    -> (sprintf "IPSECKEY (%d, %s,%s, %s, '%s')" (Cstruct.byte_to_int precedence)
          (gateway_tc_to_string gw_type) (ipseckey_alg_to_string alg)
          (gateway_to_string gw) pubkey
    )
  | NSEC (next_name, tbms)
    -> (sprintf "NSEC (%s, %s)"
          (Name.to_string next_name) (type_bit_maps_to_string tbms)
    )
  | NSEC3 (halg, flgs, iterations, salt_l, salt, hash_l, next_name, tbms)
    -> (sprintf "NSEC3 (%s, %x, %d, %d,'%s', %d,'%s', %s)"
          (hash_alg_to_string halg) (Cstruct.byte_to_int flgs) iterations
          (Cstruct.byte_to_int salt_l) salt (Cstruct.byte_to_int  hash_l) next_name
          (type_bit_maps_to_string tbms)
    )
  | NSEC3PARAM (halg, flgs, iterations, salt_l, salt)
    -> (sprintf "NSEC3PARAM (%s,%x, %d, %d, '%s')"
          (hash_alg_to_string halg) (Cstruct.byte_to_int flgs) iterations
          (Cstruct.byte_to_int salt_l) salt
    )
 | SSHFP (alg, fpt, fp)
    -> (sprintf "SSHFP (%s,%s, '%s')" (pubkey_alg_to_string alg)
          (fp_type_to_string fpt) fp
    )
let rdata_to_rr_type = function
 | A _        ->  RR_A
 | AAAA _      -> RR_AAAA
 | AFSDB _     -> RR_AFSDB
 | CNAME _     -> RR_CNAME
 | DNSKEY _    -> RR_DNSKEY
 | DS _        -> RR_DS
 | HINFO _     -> RR_HINFO
 | IPSECKEY _  -> RR_IPSECKEY
 | ISDN _      -> RR_ISDN
 | MB _        -> RR_MB
 | MD _        -> RR_MD
 | MF _        -> RR_MF
 | MG _        -> RR_MG
 | MINFO _     -> RR_MINFO
 | MR _        -> RR_MR
 | MX _        -> RR_MX
 | NS _        -> RR_NS
 | NSEC _      -> RR_NSEC
 | NSEC3 _     -> RR_NSEC3
 | NSEC3PARAM _-> RR_NSEC3PARAM
 | PTR _       -> RR_PTR
 | RP _        -> RR_RP
 | RRSIG _     -> RR_RRSIG
 | SIG _     -> RR_SIG
 | RT _        -> RR_RT
 | SOA _       -> RR_SOA
 | SRV _       -> RR_SRV
 | SSHFP _     -> RR_SSHFP
 | TXT _       -> RR_TXT
 | UNKNOWN _   -> RR_UNSPEC
 | WKS _       -> RR_WKS
 | X25 _       -> RR_X25
 | EDNS0 _     -> RR_OPT

[%%cenum
type rr_class =
  | RR_IN  [@id 1]
  | RR_CS  [@id 2]
  | RR_CH  [@id 3]
  | RR_HS  [@id 4]
  | RR_ANY [@id 0xff]
  [@@uint8_t]
]

let rr_class_to_string =
  function
  |RR_IN -> "IN"
  |RR_CS -> "CS"
  |RR_CH -> "CH"
  |RR_HS -> "HS"
  |RR_ANY -> "RR_ANY"

let string_to_rr_class =
  function
  |"IN" -> Some RR_IN
  |"CS" -> Some RR_CS
  |"CH" -> Some RR_CH
  |"HS" -> Some RR_HS
  | "ANY" -> Some RR_ANY
  |_ -> None

[%%cstruct
type rr = {
  typ: uint16_t;
  cls: uint16_t;
  ttl: uint32_t;
  rdlen: uint16_t;
} [@@big_endian]
]
 
type rr = {
  name  : Name.t;
  cls   : rr_class;
  flush : bool;  (* mDNS cache flush bit *)
  ttl   : int32;
  rdata : rdata;
}

let rr_to_string rr =
  sprintf "%s <%s%s|%ld> [%s]"
    (Name.to_string rr.name) (rr_class_to_string rr.cls)
    (if rr.flush then ",flush" else "")
    rr.ttl (rdata_to_string rr.rdata)

type q_type =
|  Q_A |  Q_NS |  Q_MD |  Q_MF
|  Q_CNAME |  Q_SOA |  Q_MB
|  Q_MG |  Q_MR |  Q_NULL |  Q_WKS
|  Q_PTR |  Q_HINFO |  Q_MINFO
|  Q_MX |  Q_TXT |  Q_RP |  Q_AFSDB
|  Q_X25 |  Q_ISDN |  Q_RT |  Q_NSAP
|  Q_NSAPPTR |  Q_SIG |  Q_KEY
|  Q_PX |  Q_GPOS |  Q_AAAA |  Q_LOC
|  Q_NXT |  Q_EID |  Q_NIMLOC |  Q_SRV
|  Q_ATMA |  Q_NAPTR |  Q_KM |  Q_CERT
|  Q_A6 |  Q_DNAME |  Q_SINK |  Q_OPT
|  Q_APL |  Q_DS |  Q_SSHFP |  Q_IPSECKEY
|  Q_RRSIG |  Q_NSEC |  Q_DNSKEY |  Q_NSEC3
|  Q_NSEC3PARAM |  Q_SPF |  Q_UINFO
|  Q_UID |  Q_GID |  Q_UNSPEC |  Q_AXFR
|  Q_MAILB |  Q_MAILA |  Q_ANY_TYP
|  Q_TA |  Q_DLV
| Q_UNKNOWN of int

let q_type_to_int = function
  |  Q_A          -> 1
  |  Q_NS         -> 2
  |  Q_MD         -> 3
  |  Q_MF         -> 4
  |  Q_CNAME      -> 5
  |  Q_SOA        -> 6
  |  Q_MB         -> 7
  |  Q_MG         -> 8
  |  Q_MR         -> 9
  |  Q_NULL       -> 10
  |  Q_WKS        -> 11
  |  Q_PTR        -> 12
  |  Q_HINFO      -> 13
  |  Q_MINFO      -> 14
  |  Q_MX         -> 15
  |  Q_TXT        -> 16
  |  Q_RP         -> 17
  |  Q_AFSDB      -> 18
  |  Q_X25        -> 19
  |  Q_ISDN       -> 20
  |  Q_RT         -> 21
  |  Q_NSAP       -> 22
  |  Q_NSAPPTR    -> 23
  |  Q_SIG        -> 24
  |  Q_KEY        -> 25
  |  Q_PX         -> 26
  |  Q_GPOS       -> 27
  |  Q_AAAA       -> 28
  |  Q_LOC        -> 29
  |  Q_NXT        -> 30
  |  Q_EID        -> 31
  |  Q_NIMLOC     -> 32
  |  Q_SRV        -> 33
  |  Q_ATMA       -> 34
  |  Q_NAPTR      -> 35
  |  Q_KM         -> 36
  |  Q_CERT       -> 37
  |  Q_A6         -> 38
  |  Q_DNAME      -> 39
  |  Q_SINK       -> 40
  |  Q_OPT        -> 41
  |  Q_APL        -> 42
  |  Q_DS         -> 43
  |  Q_SSHFP      -> 44
  |  Q_IPSECKEY   -> 45
  |  Q_RRSIG      -> 46
  |  Q_NSEC       -> 47
  |  Q_DNSKEY     -> 48
  |  Q_NSEC3      -> 50
  |  Q_NSEC3PARAM -> 51
  |  Q_SPF        -> 99
  |  Q_UINFO      -> 100
  |  Q_UID        -> 101
  |  Q_GID        -> 102
  |  Q_UNSPEC     -> 103
  |  Q_AXFR       -> 252
  |  Q_MAILB      -> 253
  |  Q_MAILA      -> 254
  |  Q_ANY_TYP    -> 255
  |  Q_TA         -> 32768
  |  Q_DLV        -> 32769
  |  Q_UNKNOWN id -> id
let int_to_q_type = function
  | 1    -> Some(Q_A         )
  | 2    -> Some(Q_NS        )
  | 3    -> Some(Q_MD        )
  | 4    -> Some(Q_MF        )
  | 5    -> Some(Q_CNAME     )
  | 6    -> Some(Q_SOA       )
  | 7    -> Some(Q_MB        )
  | 8    -> Some(Q_MG        )
  | 9    -> Some(Q_MR        )
  | 10   -> Some(Q_NULL      )
  | 11   -> Some(Q_WKS       )
  | 12   -> Some(Q_PTR       )
  | 13   -> Some(Q_HINFO     )
  | 14   -> Some(Q_MINFO     )
  | 15   -> Some(Q_MX        )
  | 16   -> Some(Q_TXT       )
  | 17   -> Some(Q_RP        )
  | 18   -> Some(Q_AFSDB     )
  | 19   -> Some(Q_X25       )
  | 20   -> Some(Q_ISDN      )
  | 21   -> Some(Q_RT        )
  | 22   -> Some(Q_NSAP      )
  | 23   -> Some(Q_NSAPPTR   )
  | 24   -> Some(Q_SIG       )
  | 25   -> Some(Q_KEY       )
  | 26   -> Some(Q_PX        )
  | 27   -> Some(Q_GPOS      )
  | 28   -> Some(Q_AAAA      )
  | 29   -> Some(Q_LOC       )
  | 30   -> Some(Q_NXT       )
  | 31   -> Some(Q_EID       )
  | 32   -> Some(Q_NIMLOC    )
  | 33   -> Some(Q_SRV       )
  | 34   -> Some(Q_ATMA      )
  | 35   -> Some(Q_NAPTR     )
  | 36   -> Some(Q_KM        )
  | 37   -> Some(Q_CERT      )
  | 38   -> Some(Q_A6        )
  | 39   -> Some(Q_DNAME     )
  | 40   -> Some(Q_SINK      )
  | 41   -> Some(Q_OPT       )
  | 42   -> Some(Q_APL       )
  | 43   -> Some(Q_DS        )
  | 44   -> Some(Q_SSHFP     )
  | 45   -> Some(Q_IPSECKEY  )
  | 46   -> Some(Q_RRSIG     )
  | 47   -> Some(Q_NSEC      )
  | 48   -> Some(Q_DNSKEY    )
  | 50   -> Some(Q_NSEC3     )
  | 51   -> Some(Q_NSEC3PARAM)
  | 99   -> Some(Q_SPF       )
  | 100  -> Some(Q_UINFO     )
  | 101  -> Some(Q_UID       )
  | 102  -> Some(Q_GID       )
  | 103  -> Some(Q_UNSPEC    )
  | 252  -> Some(Q_AXFR      )
  | 253  -> Some(Q_MAILB     )
  | 254  -> Some(Q_MAILA     )
  | 255  -> Some(Q_ANY_TYP   )
  | 32768-> Some(Q_TA        )
  | 32769-> Some(Q_DLV       )
  | id   -> Some( Q_UNKNOWN id)


let q_type_to_string = function
  |  Q_A          -> "A"
  |  Q_NS         -> "NS"
  |  Q_MD         -> "MD"
  |  Q_MF         -> "MF"
  |  Q_CNAME      -> "CNAME"
  |  Q_SOA        -> "SOA"
  |  Q_MB         -> "MB"
  |  Q_MG         -> "MG"
  |  Q_MR         -> "MR"
  |  Q_NULL       -> "NULL"
  |  Q_WKS        -> "WKS"
  |  Q_PTR        -> "PTR"
  |  Q_HINFO      -> "HINFO"
  |  Q_MINFO      -> "MINFO"
  |  Q_MX         -> "MX"
  |  Q_TXT        -> "TXT"
  |  Q_RP         -> "RP"
  |  Q_AFSDB      -> "AFSDB"
  |  Q_X25        -> "X25"
  |  Q_ISDN       -> "ISDN"
  |  Q_RT         -> "RT"
  |  Q_NSAP       -> "NSAP"
  |  Q_NSAPPTR    -> "NSAPPTR"
  |  Q_SIG        -> "SIG"
  |  Q_KEY        -> "KEY"
  |  Q_PX         -> "PX"
  |  Q_GPOS       -> "GPOS"
  |  Q_AAAA       -> "AAAA"
  |  Q_LOC        -> "LOC"
  |  Q_NXT        -> "NXT"
  |  Q_EID        -> "EID"
  |  Q_NIMLOC     -> "NIMLOC"
  |  Q_SRV        -> "SRV"
  |  Q_ATMA       -> "ATMA"
  |  Q_NAPTR      -> "NAPTR"
  |  Q_KM         -> "KM"
  |  Q_CERT       -> "CERT"
  |  Q_A6         -> "A6"
  |  Q_DNAME      -> "DNAME"
  |  Q_SINK       -> "SINK"
  |  Q_OPT        -> "OPT"
  |  Q_APL        -> "APL"
  |  Q_DS         -> "DS"
  |  Q_SSHFP      -> "SSHFP"
  |  Q_IPSECKEY   -> "IPSECKEY"
  |  Q_RRSIG      -> "RRSIG"
  |  Q_NSEC       -> "NSEC"
  |  Q_DNSKEY     -> "DNSKEY"
  |  Q_NSEC3      -> "NSEC3"
  |  Q_NSEC3PARAM -> "NSEC3PARAM"
  |  Q_SPF        -> "SPF"
  |  Q_UINFO      -> "UINFO"
  |  Q_UID        -> "UID"
  |  Q_GID        -> "GID"
  |  Q_UNSPEC     -> "UNSPEC"
  |  Q_AXFR       -> "AXFR"
  |  Q_MAILB      -> "MAILB"
  |  Q_MAILA      -> "MAILA"
  |  Q_ANY_TYP    -> "ANY_TYP"
  |  Q_TA         -> "TA"
  |  Q_DLV        -> "DLV"
  |  Q_UNKNOWN id -> (sprintf "TYPE%03d" id)

let string_to_q_type = function
  |"A"          -> Some(Q_A)
  |"NS"         -> Some(Q_NS)
  |"MD"         -> Some(Q_MD)
  |"MF"         -> Some(Q_MF)
  |"CNAME"      -> Some(Q_CNAME)
  |"SOA"        -> Some(Q_SOA)
  |"MB"         -> Some(Q_MB)
  |"MG"         -> Some(Q_MG)
  |"MR"         -> Some(Q_MR)
  |"NULL"       -> Some(Q_NULL)
  |"WKS"        -> Some(Q_WKS)
  |"PTR"        -> Some(Q_PTR)
  |"HINFO"      -> Some(Q_HINFO)
  |"MINFO"      -> Some(Q_MINFO)
  |"MX"         -> Some(Q_MX)
  |"TXT"        -> Some(Q_TXT)
  |"RP"         -> Some(Q_RP)
  |"AFSDB"      -> Some(Q_AFSDB)
  |"X25"        -> Some(Q_X25)
  |"ISDN"       -> Some(Q_ISDN)
  |"RT"         -> Some(Q_RT)
  |"NSAP"       -> Some(Q_NSAP)
  |"NSAPPTR"    -> Some(Q_NSAPPTR)
  |"SIG"        -> Some(Q_SIG)
  |"KEY"        -> Some(Q_KEY)
  |"PX"         -> Some(Q_PX)
  |"GPOS"       -> Some(Q_GPOS)
  |"AAAA"       -> Some(Q_AAAA)
  |"LOC"        -> Some(Q_LOC)
  |"NXT"        -> Some(Q_NXT)
  |"EID"        -> Some(Q_EID)
  |"NIMLOC"     -> Some(Q_NIMLOC)
  |"SRV"        -> Some(Q_SRV)
  |"ATMA"       -> Some(Q_ATMA)
  |"NAPTR"      -> Some(Q_NAPTR)
  |"KM"         -> Some(Q_KM)
  |"CERT"       -> Some(Q_CERT)
  |"A6"         -> Some(Q_A6)
  |"DNAME"      -> Some(Q_DNAME)
  |"SINK"       -> Some(Q_SINK)
  |"OPT"        -> Some(Q_OPT)
  |"APL"        -> Some(Q_APL)
  |"DS"         -> Some(Q_DS)
  |"SSHFP"      -> Some(Q_SSHFP)
  |"IPSECKEY"   -> Some(Q_IPSECKEY)
  |"RRSIG"      -> Some(Q_RRSIG)
  |"NSEC"       -> Some(Q_NSEC)
  |"DNSKEY"     -> Some(Q_DNSKEY)
  |"NSEC3"      -> Some(Q_NSEC3)
  |"NSEC3PARAM" -> Some(Q_NSEC3PARAM)
  |"SPF"        -> Some(Q_SPF)
  |"UINFO"      -> Some(Q_UINFO)
  |"UID"        -> Some(Q_UID)
  |"GID"        -> Some(Q_GID)
  |"UNSPEC"     -> Some(Q_UNSPEC)
  |"AXFR"       -> Some(Q_AXFR)
  |"MAILB"      -> Some(Q_MAILB)
  |"MAILA"      -> Some(Q_MAILA)
  |"ANY_TYP"    -> Some(Q_ANY_TYP)
  |"TA"         -> Some(Q_TA)
  |"DLV"        -> Some(Q_DLV)
  | value       ->
    let len = String.length value in
    if len < 5 || String.sub value 0 4 <> "TYPE"
    then None
    else try let i = int_of_string (String.sub value 4 (len - 4)) in
             Some (Q_UNKNOWN i)
      with Failure _ -> None

let q_type_matches_rr_type qt rrt = match qt, rrt with
  | Q_A,  RR_A
  | Q_NS, RR_NS
  | Q_MD, RR_MD
  | Q_MF, RR_MF
  | Q_CNAME, RR_CNAME
  | Q_SOA,   RR_SOA
  | Q_MB,    RR_MB
  | Q_MG,    RR_MG
  | Q_MR,    RR_MR
  | Q_NULL,  RR_NULL
  | Q_WKS,   RR_WKS
  | Q_PTR,   RR_PTR
  | Q_HINFO, RR_HINFO
  | Q_MINFO, RR_MINFO
  | Q_MX,    RR_MX
  | Q_TXT,   RR_TXT
  | Q_RP,    RR_RP
  | Q_AFSDB, RR_AFSDB
  | Q_X25,   RR_X25
  | Q_ISDN,  RR_ISDN
  | Q_RT,    RR_RT
  | Q_NSAP,  RR_NSAP
  | Q_NSAPPTR, RR_NSAPPTR
  | Q_SIG,     RR_SIG
  | Q_KEY,     RR_KEY
  | Q_PX,      RR_PX
  | Q_GPOS,    RR_GPOS
  | Q_AAAA,    RR_AAAA
  | Q_LOC,     RR_LOC
  | Q_NXT,     RR_NXT
  | Q_EID,     RR_EID
  | Q_NIMLOC,  RR_NIMLOC
  | Q_SRV,     RR_SRV
  | Q_ATMA,    RR_ATMA
  | Q_NAPTR,   RR_NAPTR
  | Q_KM,      RR_KM
  | Q_CERT,    RR_CERT
  | Q_A6,      RR_A6
  | Q_DNAME,   RR_DNAME
  | Q_SINK,    RR_SINK
  | Q_OPT,     RR_OPT
  | Q_APL,     RR_APL
  | Q_DS,      RR_DS
  | Q_SSHFP,   RR_SSHFP
  | Q_IPSECKEY, RR_IPSECKEY
  | Q_RRSIG,    RR_RRSIG
  | Q_NSEC,     RR_NSEC
  | Q_DNSKEY,   RR_DNSKEY
  | Q_NSEC3,    RR_NSEC3
  | Q_NSEC3PARAM, RR_NSEC3PARAM
  | Q_SPF,        RR_SPF
  | Q_UINFO,      RR_UINFO
  | Q_UID,        RR_UID
  | Q_GID,        RR_GID
  | Q_UNSPEC,     RR_UNSPEC
  | Q_ANY_TYP,    _ -> true
  | Q_A,  _
  | Q_NS, _
  | Q_MD, _
  | Q_MF, _
  | Q_CNAME, _
  | Q_SOA,   _
  | Q_MB,    _
  | Q_MG,    _
  | Q_MR,    _
  | Q_NULL,  _
  | Q_WKS,   _
  | Q_PTR,   _
  | Q_HINFO, _
  | Q_MINFO, _
  | Q_MX,    _
  | Q_TXT,   _
  | Q_RP,    _
  | Q_AFSDB, _
  | Q_X25,   _
  | Q_ISDN,  _
  | Q_RT,    _
  | Q_NSAP,  _
  | Q_NSAPPTR, _
  | Q_SIG,     _
  | Q_KEY,     _
  | Q_PX,      _
  | Q_GPOS,    _
  | Q_AAAA,    _
  | Q_LOC,     _
  | Q_NXT,     _
  | Q_EID,     _
  | Q_NIMLOC,  _
  | Q_SRV,     _
  | Q_ATMA,    _
  | Q_NAPTR,   _
  | Q_KM,      _
  | Q_CERT,    _
  | Q_A6,      _
  | Q_DNAME,   _
  | Q_SINK,    _
  | Q_OPT,     _
  | Q_APL,     _
  | Q_DS,      _
  | Q_SSHFP,   _
  | Q_IPSECKEY, _
  | Q_RRSIG,    _
  | Q_NSEC,     _
  | Q_DNSKEY,   _
  | Q_NSEC3,    _
  | Q_NSEC3PARAM, _
  | Q_SPF,        _
  | Q_UINFO,      _
  | Q_UID,        _
  | Q_GID,        _
  | Q_UNSPEC,     _
  | Q_AXFR,       _
  | Q_MAILA,      _
  | Q_MAILB,      _
  | Q_TA,         _
  | Q_DLV,        _
  | Q_UNKNOWN _,  _ -> false

(*let q_type_to_string x =
  let x = q_type_to_string x in
  String.sub x 2 (String.length x - 2)
let string_to_q_type x =
  string_to_q_type ("Q_"^x) *)


[%%cenum
type q_class =
  | Q_IN      [@id 1]
  | Q_CS      [@id 2]
  | Q_CH      [@id 3]
  | Q_HS      [@id 4]
  | Q_NONE    [@id 254]
  | Q_ANY_CLS [@id 255]
  [@@uint8_t]
]

let q_class_to_string x =
  let x = q_class_to_string x in
  String.sub x 2 (String.length x - 2)

let string_to_q_class x =
  string_to_q_class ("Q_"^x)

type q_unicast = Q_Normal | Q_mDNS_Unicast

let q_unicast_to_string x =
  match x with
  | Q_Normal -> "Q_Normal"
  | Q_mDNS_Unicast -> "Q_mDNS_Unicast"

[%%cstruct
type q = {
  typ: uint16_t;
  cls: uint16_t;
} [@@big_endian]
]

type question = {
  q_name    : Name.t;
  q_type    : q_type;
  q_class   : q_class;
  q_unicast : q_unicast;
}

let make_question ?(q_class=Q_IN) ?(q_unicast=Q_Normal) q_type q_name =
  { q_name; q_type; q_class; q_unicast; }

let question_to_string q =
  sprintf "%s. <%s|%s%s>"
    (Name.to_string q.q_name)
    (q_type_to_string q.q_type) (q_class_to_string q.q_class)
    (if q.q_unicast = Q_mDNS_Unicast then "|QU" else "")

let parse_question names base buf =
  let q_name, (base,buf) = Name.parse names base buf in
  let q_type =
    let typ = get_q_typ buf in
    match int_to_q_type typ with
      | None -> failwith (sprintf "parse_question: typ %d" typ)
      | Some typ -> typ
  in
  let q_class, q_unicast =
    let cls = get_q_cls buf in
    (* mDNS uses bit 15 as the unicast-response bit *)
    let q_unicast = if (((cls lsr 15) land 1) = 1) then Q_mDNS_Unicast else Q_Normal in
    match int_to_q_class (cls land 0x7FFF) with
      | None -> failwith (sprintf "parse_question: cls %d" cls)
      | Some cls -> cls, q_unicast
  in
  { q_name; q_type; q_class; q_unicast; }, (base+sizeof_q, Cstruct.shift buf sizeof_q)

let marshal_question ?(_compress=true) (names, base, buf) q =
  let names, base, buf = Name.marshal names base buf q.q_name in
  set_q_typ buf (q_type_to_int q.q_type);
  let q_unicast = (if q.q_unicast = Q_mDNS_Unicast then 1 else 0) in
  set_q_cls buf ((q_unicast lsl 15) lor (q_class_to_int q.q_class));
  names, base+sizeof_q, Cstruct.shift buf sizeof_q

exception Not_implemented

let parse_rdata names base t cls ttl buf =
  (** Drop remainder of buf to stop parsing and demuxing. *)
  let stop (x, _) = x in
  (** Extract (length, string) encoded strings, with remainder for
      chaining. *)
  let parse_charstr buf =
    let len = Cstruct.get_uint8 buf 0 in
      Cstruct.to_string (Cstruct.sub buf 1 len), Cstruct.shift buf (1+len)
  in
  match t with
    | RR_OPT ->
        let rcode = Int32.to_int (Int32.shift_right ttl 24) in
        let do_bit = ((Int32.logand ttl 0x8000l) = 0x8000l) in
          (* TODO: add here some code to parse the options of the edns rr *)
        EDNS0 (cls, rcode, do_bit, [])

    | RR_RRSIG ->
        let typ =
          let a = Cstruct.BE.get_uint16 buf 0 in
          match (int_to_rr_type a) with
            | None -> RR_UNSPEC
            | Some a -> a
        in
        let alg =
          let a =Cstruct.get_uint8 buf 2 in
            match (int_to_dnssec_alg a) with
              | None -> failwith (sprintf "parse_rdata: DNSKEY alg %d" a)
              | Some a -> a
        in
        let lbl = char_of_int (Cstruct.get_uint8 buf 3) in
        let orig_ttl = Cstruct.BE.get_uint32 buf 4 in
        let exp_ts = Cstruct.BE.get_uint32 buf 8 in
        let inc_ts = Cstruct.BE.get_uint32 buf 12 in
        let tag = Cstruct.BE.get_uint16 buf 16 in
        let buf = Cstruct.shift buf 18 in
        let (name, (_len, buf)) = Name.parse names (base+18) buf in
        let sign = Cstruct.to_string buf in
          RRSIG (typ, alg, lbl, orig_ttl, exp_ts, inc_ts, tag, name, sign)

    | RR_SIG ->
       let alg =
          let a =Cstruct.get_uint8 buf 2 in
            match (int_to_dnssec_alg a) with
              | None -> failwith (sprintf "parse_rdata: DNSKEY alg %d" a)
              | Some a -> a
        in
        let exp_ts = Cstruct.BE.get_uint32 buf 8 in
        let inc_ts = Cstruct.BE.get_uint32 buf 12 in
        let tag = Cstruct.BE.get_uint16 buf 16 in
        let buf = Cstruct.shift buf 18 in
        let (name, (_len, buf)) = Name.parse names (base+18) buf in
        let sign = Cstruct.to_string buf in
          SIG (alg, exp_ts, inc_ts, tag, name, sign)

    | RR_A -> A Cstruct.(Ipaddr.V4.of_int32 (BE.get_uint32 buf 0))

    | RR_AAAA -> AAAA (Ipaddr.V6.of_int64 Cstruct.((BE.get_uint64 buf 0),(BE.get_uint64 buf 8)))

    | RR_AFSDB -> AFSDB (Cstruct.BE.get_uint16 buf 0,
                         Cstruct.shift buf 2 |> Name.parse names (base+2) |> stop)

    | RR_CNAME -> CNAME (buf |> Name.parse names base |> stop)

    | RR_DNSKEY ->
        let flags = Cstruct.BE.get_uint16 buf 0 in
        let alg =
          let a = Cstruct.get_uint8 buf 3 in
          match int_to_dnssec_alg a with
            | None -> failwith (sprintf "parse_rdata: DNSKEY alg %d" a)
            | Some a -> a
        in
        let key = Cstruct.(shift buf 4 |> to_string) in
        DNSKEY (flags, alg, key)
    | RR_DS ->
        let tag = Cstruct.BE.get_uint16 buf 0 in
        let alg =
          match (int_to_dnssec_alg (Cstruct.get_uint8 buf 2)) with
          | Some a -> a
          | None -> failwith "parse_rdata unsupported dnssec_alg id"
        in
        let digest =
          match (int_to_digest_alg (Cstruct.get_uint8 buf 3)) with
          |Some a -> a
          | None -> failwith "parse_rdata unsupported hash algorithm id"
        in
        let key = Cstruct.(shift buf 4 |> to_string) in
          DS(tag, alg, digest, key)
    | RR_NSEC ->
        let (name, (_base, buf)) = Name.parse names base buf in
        NSEC (name, [(char_of_int 0), (char_of_int 0), buf] )

    | RR_HINFO -> let cpu, buf = parse_charstr buf in
                  let os = buf |> parse_charstr |> stop in
                  HINFO (cpu, os)

    | RR_ISDN -> let a, buf = parse_charstr buf in
                 let sa = match Cstruct.len buf with
                   | 0 -> None
                   | _ -> Some (buf |> parse_charstr |> stop)
                 in
                 ISDN (a, sa)

    | RR_MB -> MB (buf |> Name.parse names base |> stop)
    | RR_MD -> MD (buf |> Name.parse names base |> stop)
    | RR_MF -> MF (buf |> Name.parse names base |> stop)

    | RR_MG -> MG (buf |> Name.parse names base |> stop)

    | RR_MINFO -> let rm, (base,buf) = buf |> Name.parse names base in
                  let em = buf |> Name.parse names base |> stop in
                  MINFO (rm, em)

    | RR_MR -> MR (buf |> Name.parse names base |> stop)

    | RR_MX -> MX (Cstruct.BE.get_uint16 buf 0,
                   Cstruct.shift buf 2 |> Name.parse names (base+2) |> stop)

    | RR_NS -> NS (buf |> Name.parse names base |> stop)

    | RR_PTR -> PTR (buf |> Name.parse names base |> stop)

    | RR_RP -> let mbox, (base,buf) = buf |> Name.parse names base in
               let txt = buf |> Name.parse names base |> stop in
               RP (mbox, txt)

    | RR_RT -> RT (Cstruct.BE.get_uint16 buf 0,
                   Cstruct.shift buf 2 |> Name.parse names (base+2) |> stop)

    | RR_SOA ->
        let mn, (base, buf) = Name.parse names base buf in
        let rn, (_, buf) = Name.parse names base buf in
        Cstruct.BE.(SOA (mn, rn,
                 get_uint32 buf 0,  (* serial *)
                 get_uint32 buf 4,  (* refresh *)
                 get_uint32 buf 8,  (* retry *)
                 get_uint32 buf 12, (* expire *)
                 get_uint32 buf 16  (* minimum *)
        ))

    | RR_SRV ->
        Cstruct.(BE.(
          SRV (get_uint16 buf 0, (* prio *)
               get_uint16 buf 2, (* weight *)
               get_uint16 buf 4, (* port *)
               shift buf 6 |> Name.parse names (base+6) |> stop
          )))

    | RR_TXT ->
        let strings =
          let rec aux strings buf =
            match Cstruct.len buf with
              | 0 -> List.rev strings
              | _len ->
                  let s, buf = parse_charstr buf in
                  aux (s :: strings) buf
          in
          aux [] buf
        in
        TXT strings

    | RR_WKS ->
        let addr = Ipaddr.V4.of_int32 (Cstruct.BE.get_uint32 buf 0) in
        let proto = Cstruct.get_uint8 buf 4 in
        let bitmap = Cstruct.(shift buf 5 |> to_string) in
        WKS (addr, Cstruct.byte proto, bitmap)

    | RR_X25 ->
        let x25,_ = parse_charstr buf in
        X25 x25
    | _ -> raise Not_implemented

  let marshal_rdata names ?(compress=true) base rdbuf = function
    | A ip ->
        Cstruct.BE.set_uint32 rdbuf 0 (Ipaddr.V4.to_int32 ip);
        RR_A, names, 4
    | AAAA ip ->
        let s1,s2 = Ipaddr.V6.to_int64 ip in
        Cstruct.BE.set_uint64 rdbuf 0 s1;
        Cstruct.BE.set_uint64 rdbuf 8 s2;
        RR_AAAA, names, 16
    | AFSDB (x,name) ->
        Cstruct.BE.set_uint16 rdbuf 0 x;
        let names, offset, _ =
          Name.marshal ~compress names (base+2) (Cstruct.shift rdbuf 2) name
       in
        RR_AFSDB, names, offset-base
    | CNAME name ->
        let names, offset, _ = Name.marshal ~compress names base rdbuf name in
        RR_CNAME, names, offset-base
    | DNSKEY (flags, alg, key) ->
        Cstruct.BE.set_uint16 rdbuf 0 flags;
        Cstruct.set_uint8 rdbuf 2 3;
        Cstruct.set_uint8 rdbuf 3 (dnssec_alg_to_int alg);
        let slen = String.length key in
        Cstruct.blit_from_string key 0 rdbuf 4 slen;
        RR_DNSKEY, names, 4+slen
    | DS (tag, alg, digest, key) ->
        Cstruct.BE.set_uint16 rdbuf 0 tag;
        Cstruct.set_uint8 rdbuf 2 (dnssec_alg_to_int alg);
        Cstruct.set_uint8 rdbuf 3 (digest_alg_to_int digest);
        let slen = String.length key in
        Cstruct.blit_from_string key 0 rdbuf 4 slen;
        RR_DS, names, 4+slen
     | RRSIG (typ, alg, lbl, orig_ttl, exp_ts, inc_ts, tag, name, sign) ->
        let _ = Cstruct.BE.set_uint16 rdbuf 0 (rr_type_to_int typ) in
        let _ = Cstruct.set_uint8 rdbuf 2 (dnssec_alg_to_int alg) in
        let _ = Cstruct.set_uint8 rdbuf 3 (int_of_char lbl) in
        let _ = Cstruct.BE.set_uint32 rdbuf 4 orig_ttl in
        let _ = Cstruct.BE.set_uint32 rdbuf 8 exp_ts in
        let _ = Cstruct.BE.set_uint32 rdbuf 12 inc_ts in
        let _ = Cstruct.BE.set_uint16 rdbuf 16 tag in
        let rdbuf = Cstruct.shift rdbuf 18 in
        let (names, len, rdbuf) = Name.marshal ~compress names 0 rdbuf name in
        let _ = Cstruct.blit_from_string sign 0 rdbuf 0 (String.length sign) in
          RR_RRSIG, names, (18+len+(String.length sign))
     | SIG (alg, exp_ts, inc_ts, tag, name, sign) ->
        let _ = Cstruct.BE.set_uint16 rdbuf 0 0 in
        let _ = Cstruct.set_uint8 rdbuf 2 (dnssec_alg_to_int alg) in
        let _ = Cstruct.set_uint8 rdbuf 3 0 in
        let _ = Cstruct.BE.set_uint32 rdbuf 4 0l in
        let _ = Cstruct.BE.set_uint32 rdbuf 8 exp_ts in
        let _ = Cstruct.BE.set_uint32 rdbuf 12 inc_ts in
        let _ = Cstruct.BE.set_uint16 rdbuf 16 tag in
        let rdbuf = Cstruct.shift rdbuf 18 in
        let (names, len, rdbuf) = Name.marshal ~compress names 0 rdbuf name in
        let _ = Cstruct.blit_from_string sign 0 rdbuf 0 (String.length sign) in
          RR_SIG, names, (18+len+(String.length sign))
     | HINFO (cpu,os) ->
        let cpustr, cpulen = charstr cpu in
        Cstruct.blit_from_string cpustr 0 rdbuf 0 cpulen;
        let osstr, oslen = charstr os in
        Cstruct.blit_from_string osstr 0 rdbuf cpulen oslen;
        RR_HINFO, names, cpulen+oslen
    | ISDN (a,sa) ->
        let astr, alen = charstr a in
        Cstruct.blit_from_string astr 0 rdbuf 0 alen;
        let sastr, salen = match sa with
          | None -> "", 0
          | Some sa -> charstr sa
        in
        Cstruct.blit_from_string sastr 0 rdbuf alen salen;
        RR_ISDN, names, alen+salen
    | MB name ->
        let names, offset, _ = Name.marshal ~compress names base rdbuf name in
        RR_MB, names, offset-base
    | MD name ->
        let names, offset, _ = Name.marshal ~compress names base rdbuf name in
        RR_MD, names, offset-base
    | MF name ->
        let names, offset, _ = Name.marshal ~compress names base rdbuf name in
        RR_MF, names, offset-base
    | MG name ->
        let names, offset, _ = Name.marshal ~compress names base rdbuf name in
        RR_MG, names, offset-base
    | MINFO (rm,em) ->
        let names, offset, rdbuf = Name.marshal ~compress names base rdbuf rm in
        let names, offset, _ = Name.marshal ~compress names offset rdbuf em in
        RR_MINFO, names, offset-base
    | MR name ->
        let names, offset, _ = Name.marshal ~compress names base rdbuf name in
        RR_MR, names, offset-base
    | MX (pref,xchg) ->
        Cstruct.BE.set_uint16 rdbuf 0 pref;
        let names, offset, _ =
          Name.marshal ~compress names (base+2) (Cstruct.shift rdbuf 2) xchg
        in
        RR_MX, names, offset-base
    | NS name ->
        let names, offset, _ = Name.marshal ~compress names base rdbuf name in
        RR_NS, names, offset-base
    | RP (mbox,txt) ->
        let names, offset, rdbuf = Name.marshal ~compress names base rdbuf mbox in
        let names, offset, _ = Name.marshal ~compress names offset rdbuf txt in
        RR_RP, names, offset-base
    | RT (x, name) ->
        Cstruct.BE.set_uint16 rdbuf 0 x;
        let names, offset, _ =
          Name.marshal ~compress names (base+2) (Cstruct.shift rdbuf 2) name
        in
        RR_RT, names, offset-base
    | PTR name ->
        let names, offset, _ = Name.marshal ~compress names base rdbuf name in
        RR_PTR, names, offset-base
    | SOA (mn,rn, serial, refresh, retry, expire, minimum) ->
        let names, offset, rdbuf = Name.marshal ~compress names base rdbuf mn in
        let names, offset, rdbuf = Name.marshal ~compress names offset rdbuf rn in
        Cstruct.BE.set_uint32 rdbuf 0 serial;
        Cstruct.BE.set_uint32 rdbuf 4 refresh;
        Cstruct.BE.set_uint32 rdbuf 8 retry;
        Cstruct.BE.set_uint32 rdbuf 12 expire;
        Cstruct.BE.set_uint32 rdbuf 16 minimum;
        RR_SOA, names, 20+offset-base
    | SRV (prio, weight, port, name) ->
        Cstruct.BE.set_uint16 rdbuf 0 prio;
        Cstruct.BE.set_uint16 rdbuf 2 weight;
        Cstruct.BE.set_uint16 rdbuf 4 port;
        let names, offset, _ =
          Name.marshal ~compress names (base+6) (Cstruct.shift rdbuf 6) name
        in
        RR_SRV, names, offset-base
    | TXT strings ->
        RR_TXT, names, List.fold_left (fun acc s ->
          let s, slen = charstr s in
          Cstruct.blit_from_string s 0 rdbuf acc slen;
          acc+slen
        ) 0 strings
    | WKS (a,p, bm) ->
        Cstruct.BE.set_uint32 rdbuf 0 (Ipaddr.V4.to_int32 a);
        Cstruct.set_uint8 rdbuf 4 (Cstruct.byte_to_int p);
        let bmlen = String.length bm in
        Cstruct.blit_from_string bm 0 rdbuf 5 bmlen;
        RR_WKS, names, 5+bmlen
    | X25 x25 ->
        let s,slen = charstr x25 in
        Cstruct.blit_from_string s 0 rdbuf 0 slen;
        RR_X25, names, slen
    | EDNS0 (_len, _rcode, _do_bit, _) ->
       RR_OPT, names, 0
    | UNKNOWN (_typ, data) ->
        Cstruct.blit_from_string data 0 rdbuf 0 (String.length data);
        RR_UNSPEC, names, (String.length data)
    | _ -> raise Not_implemented

  let compare_rdata a_rdata b_rdata =
    match (a_rdata, b_rdata) with
    | A a_ip, A b_ip -> Ipaddr.V4.compare a_ip b_ip
    | AAAA a_ip, AAAA b_ip -> Ipaddr.V6.compare a_ip b_ip
    | X25 a, X25 b -> String.compare a b
    | AFSDB (a_x,a_name), AFSDB (b_x, b_name) ->
        if (a_x = b_x) then
          Name.dnssec_compare a_name b_name
        else
          compare a_x b_x
    | DNSKEY (a_f, a_a, a_k), DNSKEY (b_f, b_a, b_k)->
        if (a_f = b_f) then
          (if (dnssec_alg_to_int a_a) = (dnssec_alg_to_int b_a) then
            String.compare a_k b_k
          else
            compare (dnssec_alg_to_int a_a) (dnssec_alg_to_int b_a)
          ) else
            compare a_f b_f
    | MB a, MB b  | MD a, MD b | MF a, MF b | MG a, MG b
    | MR a, MR b | NS a, NS b | PTR a, PTR b
    | CNAME a, CNAME b ->
        Name.dnssec_compare a b
    | TXT a, TXT b -> Name.dnssec_compare_str a b
(*| DS (tag, alg, digest, key) ->
  | HINFO (cpu,os) ->
  | ISDN (a,sa) ->
  | MINFO (rm,em) ->
  | MX (pref,xchg) ->
  | RP (mbox,txt) ->
  | RT (x, name) ->
  | SOA (mn,rn, serial, refresh, retry, expire, minimum) ->
  | SRV (prio, weight, port, name) ->
  | WKS (a,p, bm) ->*)
  | RRSIG _, RRSIG _ ->  failwith "cannot compare RRSIG"
  | EDNS0 _, EDNS0 _ -> failwith "cannot compare EDNS0"
  | _ -> failwith (sprintf "unsported rdata compare : %s - %s"
                    (rdata_to_string a_rdata) (rdata_to_string b_rdata))
let parse_rr names base buf =
  let name, (base,buf) = Name.parse names base buf in
  let t = get_rr_typ buf in
  match int_to_rr_type t with
    | None ->
        let ttl = get_rr_ttl buf in
        let rdlen = get_rr_rdlen buf in
        let cls =
          match int_to_rr_class (get_rr_cls buf) with
          | None -> failwith "invalid RR class"
          | Some cls -> cls in
        let data = Cstruct.to_string
        (Cstruct.sub buf sizeof_rr rdlen) in
        ({name; cls; flush=false; ttl; rdata=UNKNOWN(t, data) },
          ((base+sizeof_rr+rdlen), Cstruct.shift buf (sizeof_rr+rdlen))
        )
    | Some typ ->
        let ttl = get_rr_ttl buf in
        let rdlen = get_rr_rdlen buf in
        let cls = get_rr_cls buf in
        let rdata =
          let rdbuf = Cstruct.sub buf sizeof_rr rdlen in
          parse_rdata names (base+sizeof_rr) typ cls ttl rdbuf
        in
        match typ with
          | RR_OPT ->
              ({ name; cls=RR_IN; flush=false; ttl; rdata },
               ((base+sizeof_rr+rdlen),
               Cstruct.shift buf (sizeof_rr+rdlen))
              )
          | _ ->
            (* mDNS uses bit 15 as cache flush flag *)
            let flush = (((cls lsr 15) land 1) = 1) in
            match ((cls land 0x7FFF) |> int_to_rr_class) with
              | Some cls ->
                  ({ name; cls; flush; ttl; rdata },
                   ((base+sizeof_rr+rdlen),
                   Cstruct.shift buf (sizeof_rr+rdlen))
                  )
              | None -> failwith "parse_rr: unknown class"

let marshal_rr ?(compress=true) (names, base, buf) rr =
  let names, base, buf = Name.marshal ~compress names base
                          buf rr.name in
  let base, rdbuf = base+sizeof_rr, Cstruct.shift buf sizeof_rr in
  let t, names, rdlen = marshal_rdata names ~compress base
                          rdbuf rr.rdata in
  set_rr_typ buf (rr_type_to_int t);
  set_rr_rdlen buf rdlen;
  (* in case the record is an edns field, we need to treat it specially
   * for its ttl and class fields. *)
  let _ = match rr.rdata with
  | EDNS0 (len, rcode, do_bit, _) ->
      let _ = set_rr_cls buf len in
      let ttl =
        Int32.logor
          (Int32.shift_left (Int32.of_int rcode) 24)
          (Int32.shift_left (if (do_bit) then 1l else 0l) 15)
      in
        set_rr_ttl buf ttl
  | UNKNOWN (typ, _) ->
      set_rr_typ buf typ;
      let _ = set_rr_cls buf (rr_class_to_int rr.cls) in
      let _ = set_rr_ttl buf rr.ttl in
        ()
  | _ ->
      let flush = (if rr.flush then 1 else 0) in
      let cls = rr_class_to_int rr.cls in
      set_rr_cls buf ((flush lsl 15) lor cls);
      set_rr_ttl buf rr.ttl
  in
  names, base+rdlen, Cstruct.shift buf (sizeof_rr+rdlen)

[%%cenum
type qr =
  | Query    [@id 0]
  | Response [@id 1]
  [@@uint8_t]
]

type opcode =
  | Standard        (*ID: 0*)
  | Inverse         (*ID: 1*)
  | Status          (*ID: 2*)
  | Notify          (*ID: 4*)
  | Update          (*ID: 5*)
  | Reserved of int (*ID: either 3 or 6-15*)

let opcode_to_int opcode = match opcode with
  | Standard -> 0
  | Inverse -> 1
  | Status -> 2
  | Notify -> 4
  | Update -> 5
  | Reserved k -> match k with
    | 0 | 1 | 2 | 4 | 5 -> failwith (sprintf "bad opcode: %d exists and is not reserved" k)
    | _ -> k

let int_to_opcode n = match n with
  | 0 -> Standard
  | 1 -> Inverse
  | 2 -> Status
  | 4 -> Notify
  | 5 -> Update
  | k when k <= 15 -> Reserved k
  | k -> failwith (sprintf "bad opcode: %d is not on 4 bits" k)

let opcode_to_string opcode = match opcode with
  | Standard -> "Query"
  | Inverse -> "IQuery"
  | Status -> "Status"
  | Notify -> "Notify"
  | Update -> "Update"
  | Reserved k -> sprintf "Reserved%d" k



[%%cenum
type rcode =
  | NoError  [@id 0]
  | FormErr  [@id 1]
  | ServFail [@id 2]
  | NXDomain [@id 3]
  | NotImp   [@id 4]
  | Refused  [@id 5]
  | YXDomain [@id 6]
  | YXRRSet  [@id 7]
  | NXRRSet  [@id 8]
  | NotAuth  [@id 9]
  | NotZone  [@id 10]

  | BadVers  [@id 16]
  | BadKey   [@id 17]
  | BadTime  [@id 18]
  | BadMode  [@id 19]
  | BadName  [@id 20]
  | BadAlg   [@id 21]
  [@@uint8_t]
]

[%%cstruct
type h = {
  id: uint16_t;
  detail: uint16_t;
  qdcount: uint16_t;
  ancount: uint16_t;
  nscount: uint16_t;
  arcount: uint16_t;
} [@@big_endian]
]

type detail = {
  qr: qr;
  opcode: opcode;
  aa: bool;
  tc: bool;
  rd: bool;
  ra: bool;
  rcode: rcode;
}

let marshal_detail d =
  (qr_to_int d.qr lsl 15)
  lor (opcode_to_int d.opcode lsl 11)
    lor (if d.aa then 1 lsl 10 else 0)
      lor (if d.tc then 1 lsl  9 else 0)
        lor (if d.rd then 1 lsl 8 else 0)
          lor (if d.ra then 1 lsl 7 else 0)
            lor (rcode_to_int d.rcode)

let detail_to_string d =
  sprintf "%s:%d %s:%s:%s:%s %d"
    (qr_to_string d.qr)
    (opcode_to_int d.opcode)
    (if d.aa then "a" else "na") (* authoritative vs not *)
    (if d.tc then "t" else "c") (* truncated vs complete *)
    (if d.rd then "r" else "nr") (* recursive vs not *)
    (if d.ra then "ra" else "rn") (* recursion available vs not *)
    (rcode_to_int d.rcode)

let parse_detail d =
  let qr = match (d lsr 15 land 1) |> int_to_qr with
    | Some qr -> qr
    | None -> failwith "bad qr"
  in
  let opcode = int_to_opcode (d lsr 11 land 0b0_1111)
  in
  let int_to_bool = function
    | 0 -> false
    | _ -> true
  in
  let aa = (d lsr 10 land 1) |> int_to_bool in
  let tc = (d lsr  9 land 1) |> int_to_bool in
  let rd = (d lsr  8 land 1) |> int_to_bool in
  let ra = (d lsr  7 land 1) |> int_to_bool in
  let rcode = match (d land 0b0_1111) |> int_to_rcode with
    | Some rcode -> rcode
    | None -> failwith "bad rcode"
  in
  { qr; opcode; aa; tc; rd; ra; rcode }

type t = {
  id          : int;
  detail      : detail;
  questions   : question list; (* Cstruct.iter; *)
  answers     : rr list; (* Cstruct.iter; *)
  authorities : rr list; (* Cstruct.iter; *)
  additionals : rr list; (* Cstruct.iter; *)
}

let to_string d =
  sprintf "%04x %s <qs:%s> <an:%s> <au:%s> <ad:%s>"
    d.id (detail_to_string d.detail)
    (d.questions ||> question_to_string |> String.concat ",")
    (d.answers ||> rr_to_string |> String.concat ",")
    (d.authorities ||> rr_to_string |> String.concat ",")
    (d.additionals ||> rr_to_string |> String.concat ",")

let parse buf =
  let names = Hashtbl.create 32 in
  let parsen f base n buf _typ =
    let rec aux acc n base buf =
      match n with
        | 0 -> List.rev acc, (base,buf)
        | _ ->
            let r, (base,buf) = f names base buf in
              aux (r :: acc) (n-1) base buf
    in
    aux [] n base buf
  in

  let id = get_h_id buf in
  let detail = get_h_detail buf |> parse_detail in
  let qdcount = get_h_qdcount buf in
  let ancount = get_h_ancount buf in
  let nscount = get_h_nscount buf in
  let arcount = get_h_arcount buf in

  let base = sizeof_h in
  let buf = Cstruct.shift buf base in
  let questions, (base,buf) = parsen parse_question base qdcount buf "question" in
  let answers, (base,buf) = parsen parse_rr base ancount buf "answer" in
  let authorities, (base,buf) = parsen parse_rr base nscount buf "auth" in
  let additionals, _ = parsen parse_rr base arcount buf "additional" in
  let dns = { id; detail; questions; answers; authorities; additionals } in
  (* eprintf "RX: %s\n%!" (to_string dns); *)
  dns

let marshal ?(alloc = fun () -> Cstruct.create 4096) dns =
  let txbuf = alloc () in
  let marshaln f names base buf values =
    List.fold_left f (names, base, buf) values
  in

  set_h_id txbuf dns.id;
  set_h_detail txbuf (marshal_detail dns.detail);
  set_h_qdcount txbuf (List.length dns.questions);
  set_h_ancount txbuf (List.length dns.answers);
  set_h_nscount txbuf (List.length dns.authorities);
  set_h_arcount txbuf (List.length dns.additionals);

  (** Map name (list of labels) to an offset. *)
  let names = Name.Map.empty in
  let base,buf = sizeof_h, Cstruct.shift txbuf sizeof_h in
  let names,base,buf = marshaln marshal_question names base buf dns.questions in
  let names,base,buf = marshaln marshal_rr names base buf dns.answers in
  let names,base,buf = marshaln marshal_rr names base buf dns.authorities in
  let _,_,buf = marshaln marshal_rr names base buf dns.additionals in

  let txbuf = Cstruct.(sub txbuf 0 (len txbuf - len buf)) in
  (* Cstruct.hexdump txbuf;   *)
  (* eprintf "TX: %s\n%!" (txbuf |> parse (Hashtbl.create 8) |> to_string); *)
  txbuf

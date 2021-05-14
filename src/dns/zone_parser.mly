/*
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
 *  dnsparser.mly -- ocamlyacc parser for DNS "Master zone file" format
 */

%{

open Loader

let parse_error s =
  prerr_endline ("Error (" ^ state.filename
		 ^ " line " ^ (string_of_int (state.lineno - 1))
		 ^ "): " ^ s)

let parse_warning s =
  prerr_endline ("Warning (" ^ state.filename
		 ^ " line " ^ (string_of_int state.lineno)
		 ^ "): " ^ s)

let prev_warning s =
  prerr_endline ("Warning (" ^ state.filename
		 ^ " line " ^ (string_of_int (state.lineno - 1))
		 ^ "): " ^ s)

(* Parsers for numbers *)
let parse_uint8 s =
  try let d = int_of_string s in
  if d < 0 || d > 255 then raise Parsing.Parse_error;
  d
  with Failure _ -> raise Parsing.Parse_error

let parse_byte s = Cstruct.byte (parse_uint8 s)

let parse_uint16 s =
  try
    let n = int_of_string s in
    if n > 65535 then raise Parsing.Parse_error;
    n
  with Failure _ -> raise Parsing.Parse_error


let parse_uint32 s =
  try
    let n = Int64.of_string s in
    if n >= 4294967296L then raise Parsing.Parse_error;
    Int64.to_int32 n
  with Failure _ -> raise Parsing.Parse_error


(* Parse an even-length string of hex into a bytestream *)
let parse_hexbytes s =
  let rec unhex src dst off =
    if (off < 0) then ()
    else begin
      Bytes.set dst off (char_of_int (int_of_string ("0x" ^ String.sub s (off*2) 2)));
      unhex src dst (off - 1)
    end
  in
  let slen = String.length s in
  if not (slen mod 2 = 0) then raise Parsing.Parse_error;
  let r = Bytes.create (slen / 2)
  in unhex s r (slen / 2 - 1);
  Bytes.to_string r

(* Parse a list of services into a bitmap of port numbers *)
let parse_wks proto services =
  let s2n proto service =
    match service with
      `Number s -> s
    | `Name s ->
(* XXX avsm temporarily fail until we have getservbyname *)
(*
	try (getservbyname s (getprotobynumber proto).p_name).s_port
*)
      let proto, ports = match Cstruct.byte_to_int proto with
        | 6 -> "tcp", Uri_services.tcp_port_of_service s
        | 17 -> "udp", Uri_services.udp_port_of_service s
        | n -> string_of_int n, []
      in
      match ports with
      | port::_ -> port
      | [] ->
        parse_error ("unknown service \"" ^ s ^ "\" for protocol " ^ proto);
        raise Parsing.Parse_error
  in let addport bitmap n =
    let byte = n/8 in
    let bit = 128 lsr (n mod 8) in
    Bytes.set bitmap byte (char_of_int ((int_of_char (Bytes.get bitmap byte)) lor bit))
  in
  let ports = List.map (s2n proto) services in
  let maxport = List.fold_left max 0 ports in
  let s = Bytes.make ((maxport/8)+1) '\000' in
  List.iter (addport s) ports;
  Bytes.to_string s

(* Parse an IPv6 address.  (RFC 3513 section 2.2) *)
let parse_ipv6 s =
  Ipaddr.V6.of_string_exn s

%}

%token EOF
%token EOL
%token SORIGIN
%token STTL
%token AT
%token DOT
%token SPACE
%token GENERIC
%token <string> NUMBER
%token <string> CHARSTRING

%token <string> TYPE_A
%token <string> TYPE_NS
%token <string> TYPE_MD
%token <string> TYPE_MF
%token <string> TYPE_CNAME
%token <string> TYPE_SOA
%token <string> TYPE_MB
%token <string> TYPE_MG
%token <string> TYPE_MR
%token <string> TYPE_NULL
%token <string> TYPE_WKS
%token <string> TYPE_PTR
%token <string> TYPE_HINFO
%token <string> TYPE_MINFO
%token <string> TYPE_MX
%token <string> TYPE_TXT
%token <string> TYPE_RP
%token <string> TYPE_AFSDB
%token <string> TYPE_X25
%token <string> TYPE_ISDN
%token <string> TYPE_RT
%token <string> TYPE_NSAP
%token <string> TYPE_NSAP_PTR
%token <string> TYPE_SIG
%token <string> TYPE_KEY
%token <string> TYPE_PX
%token <string> TYPE_GPOS
%token <string> TYPE_AAAA
%token <string> TYPE_LOC
%token <string> TYPE_NXT
%token <string> TYPE_EID
%token <string> TYPE_NIMLOC
%token <string> TYPE_SRV
%token <string> TYPE_ATMA
%token <string> TYPE_NAPTR
%token <string> TYPE_KX
%token <string> TYPE_CERT
%token <string> TYPE_A6
%token <string> TYPE_DNAME
%token <string> TYPE_SINK
%token <string> TYPE_OPT
%token <string> TYPE_APL
%token <string> TYPE_DS
%token <string> TYPE_SSHFP
%token <string> TYPE_IPSECKEY
%token <string> TYPE_RRSIG
%token <string> TYPE_NSEC
%token <string> TYPE_DNSKEY
%token <string> TYPE_SPF
%token <string> TYPE_UINFO
%token <string> TYPE_UID
%token <string> TYPE_GID
/* %token <string> TYPE_UNSPEC  */
%token <string> TYPE_TKEY
%token <string> TYPE_TSIG
%token <string> TYPE_MAILB
%token <string> TYPE_MAILA
%token <string> TYPE_GENERIC

%token <string> CLASS_IN
%token <string> CLASS_CS
%token <string> CLASS_CH
%token <string> CLASS_HS

%start zfile
%type <unit> zfile  /* This list is in reverse order! */

%%

zfile: lines EOF { $1 } | lines error EOF { $1 }

lines:
   /* nothing */ {}
 | lines EOL {}
 | lines origin EOL {}
 | lines ttl EOL {}
 | lines rrline EOL
     { try $2 state.db with
         TTLMismatch -> prev_warning "TTL does not match earlier RRs"
       | Name.BadDomainName s -> parse_error ("bad domain name: " ^ s)
     }
 | lines error EOL { }

s: SPACE {} | s SPACE {}

origin: SORIGIN s domain { state.origin <- $3 }

ttl: STTL s int32 { state.ttl <- $3 }

rrline:
   owner s int32 s rrclass s rr { $7 $3 $1 }
 | owner s rrclass s int32 s rr { $7 $5 $1 }
 | owner s rrclass s rr { $5 state.ttl $1 }
 | owner s int32 s rr { $5 $3 $1 }
 | owner s rr { $3 state.ttl $1 }

rrclass:
   CLASS_IN {}
 | CLASS_CS { parse_error "class must be \"IN\""; raise Parsing.Parse_error; }
 | CLASS_CH { parse_error "class must be \"IN\""; raise Parsing.Parse_error; }
 | CLASS_HS { parse_error "class must be \"IN\""; raise Parsing.Parse_error; }

rr:
   generic_type s generic_rdata { add_generic_rr $1 $3 }
     /* RFC 1035 */
 | TYPE_A s ipv4 { add_a_rr $3 }
 | TYPE_MD s domain { prev_warning "Converting MD to MX"; add_mx_rr 0 $3 }
 | TYPE_MF s domain { prev_warning "Converting MF to MX"; add_mx_rr 10 $3 }
 | TYPE_NS s domain { add_ns_rr $3 }
 | TYPE_CNAME s domain { add_cname_rr $3 }
 | TYPE_SOA s domain s domain s serial s int32 s int32 s int32 s int32
     { add_soa_rr $3 $5 $7 $9 $11 $13 $15 }
 | TYPE_MB s domain { add_mb_rr $3 }
 | TYPE_MG s domain { add_mg_rr $3 }
 | TYPE_MR s domain { add_mr_rr $3 }
     /* TYPE_NULL is not allowed in master files */
 | TYPE_WKS s ipv4 s proto s services { add_wks_rr $3 $5 (parse_wks $5 $7) }
 | TYPE_PTR s domain { add_ptr_rr $3 }
 | TYPE_HINFO s charstring s charstring { add_hinfo_rr $3 $5 }
 | TYPE_MINFO s domain s domain { add_minfo_rr $3 $5 }
 | TYPE_MX s int16 s domain { add_mx_rr $3 $5 }
 | TYPE_TXT s charstrings { add_txt_rr $3 }
     /* RFC 1183 */
 | TYPE_RP s domain s domain { add_rp_rr $3 $5 }
 | TYPE_AFSDB s int16 s domain { add_afsdb_rr $3 $5 }
 | TYPE_X25 s charstring { add_x25_rr $3 }
 | TYPE_ISDN s charstring { add_isdn_rr $3 None }
 | TYPE_ISDN s charstring s charstring { add_isdn_rr $3 (Some $5) }
 | TYPE_RT s int16 s domain { add_rt_rr $3 $5 }
     /* RFC 2782 */
 | TYPE_SRV s int16 s int16 s int16 s domain { add_srv_rr $3 $5 $7 $9 }
     /* RFC 3596 */
 | TYPE_AAAA s ipv6 { add_aaaa_rr $3 }
 | TYPE_DNSKEY s int16 s int16 s int16 s charstring {add_dnskey_rr $3 $7 $9 }
 | TYPE_RRSIG s keyword_or_number s int16 s int16 s int32 s int32 s int32 s int16 s
      domain s charstring {add_rrsig_rr $3 $5 $7 $9 $11 $13 $15 $17 $19 }
 | TYPE_DS s int16 s int16 s int16 s charstring {add_ds_rr $3 $5 $7 $9}
 /* Never properly defined: just testing the generic rdata format */
 /* | TYPE_UNSPEC s generic_rdata { add_unspec_rr $3 } */

ipv4: NUMBER DOT NUMBER DOT NUMBER DOT NUMBER
     { try
	 let a = parse_uint8 $1 in
	 let b = parse_uint8 $3 in
	 let c = parse_uint8 $5 in
	 let d = parse_uint8 $7 in
         Ipaddr.V4.make a b c d
       with Failure _ | Parsing.Parse_error ->
	 parse_error ("invalid IPv4 address " ^
		      $1 ^ "." ^ $3 ^ "." ^ $5 ^ "." ^ $7);
	 raise Parsing.Parse_error }

ipv6: ipv6str
     { try parse_ipv6 $1
       with Failure _ | Parsing.Parse_error ->
	 parse_error ("invalid IPv6 address " ^ $1);
	 raise Parsing.Parse_error }

ipv6str:
   charstring {$1}
 | charstring DOT NUMBER DOT NUMBER DOT NUMBER
     { $1 ^ "." ^ $3 ^ "." ^ $5 ^ "." ^ $7 }

serial: NUMBER
     { try
         let n = parse_uint32 $1 in
	 if not ((Int32.logand n (Int32.of_string "0x80000000")) = Int32.zero)
	 then parse_warning ("serial number " ^ $1 ^ " >= 2^32");
	 n
       with Failure _ ->
	 parse_error ("serial number " ^ $1 ^ " is not a 32-bit number");
	 raise Parsing.Parse_error
}

services: service { [$1] } | services s service { $3 :: $1 }

service: charstring
     { try `Number (parse_uint16 $1)
       with Parsing.Parse_error -> `Name $1 }

proto: charstring
/* XXX getprotobyname not implemented yet */
/*
     { try (getprotobyname $1).p_proto
*/
     { match $1 with "tcp" -> char_of_int 6 | "udp" -> char_of_int 17 | _ ->
       try parse_byte $1
       with Parsing.Parse_error ->
	 parse_error ($1 ^ " is not a known IP protocol");
	 raise Parsing.Parse_error }

/*
int8: NUMBER
     { try parse_uint8 $1
       with Parsing.Parse_error ->
	 parse_error ($1 ^ " is not an 8-bit number");
	 raise Parsing.Parse_error }
*/

int16: NUMBER
     { try parse_uint16 $1
       with Parsing.Parse_error ->
	 parse_error ($1 ^ " is not a 16-bit number");
	 raise Parsing.Parse_error }

int32: NUMBER
     { try parse_uint32 $1
       with Failure _ ->
	 parse_error ($1 ^ " is not a 32-bit number");
	 raise Parsing.Parse_error }

generic_type: TYPE_GENERIC
     { try parse_uint16 (String.sub $1 4 (String.length $1 - 4))
       with Parsing.Parse_error ->
	 parse_error ($1 ^ " is not a 16-bit number");
	 raise Parsing.Parse_error }

generic_rdata: GENERIC s NUMBER s generic_words
     { try
         let len = int_of_string $3 in
           if not (String.length $5 = len)
             then parse_warning ("generic data length field is "
				 ^ $3 ^ " but actual length is "
				 ^ (string_of_int (String.length $5)));
	 $5
       with Failure _ ->
	 parse_error ("\\# should be followed by a number");
	 raise Parsing.Parse_error }

generic_words:
   hexword { $1 }
 | generic_words s hexword { $1 ^ $3 }

hexword: charstring
     { try parse_hexbytes $1
       with Parsing.Parse_error ->
	 parse_error ($1 ^ " is not a valid sequence of hex bytes");
	 raise Parsing.Parse_error }

/* The owner of an RR is more restricted than a general domain name: it
   can't be a pure number or a type or class.  If we see one of those we
   assume the owner field was omitted */
owner:
   /* nothing */ { state.owner }
 | domain { state.owner <- $1 ; state.owner }

domain:
   DOT { Name.empty }
 | AT { state.origin }
 | label_except_at { Name.cons $1 state.origin }
 | label DOT { Name.of_string_list ([$1]) }
 | label DOT domain_labels { Name.cons $1 (Name.append (Name.of_string_list $3) state.origin) }
 | label DOT domain_labels DOT { Name.of_string_list ($1 :: $3) }

domain_labels:
   label { [$1] }
 | domain_labels DOT label { $1 @ [$3] }

/* It's acceptable to re-use numbers and keywords as character-strings.
   This is pretty ugly: we need special cases to distinguish a domain
   that's made up of just an '@'. */

charstrings: charstring { [$1] } | charstrings s charstring { $1 @ [$3] }

charstring: CHARSTRING { $1 } | keyword_or_number { $1 } | AT { "@" }

label_except_specials: CHARSTRING
    { if String.length $1 > 63 then begin
        parse_error "label is longer than 63 bytes";
        raise Parsing.Parse_error;
      end; $1 }

label_except_at: label_except_specials { $1 } | keyword_or_number { $1 }

label: label_except_at { $1 } | AT { "@" }

keyword_or_number:
   NUMBER { $1 }
 | TYPE_GENERIC { $1 }
 | TYPE_A { $1 }
 | TYPE_NS { $1 }
 | TYPE_MD { $1 }
 | TYPE_MF { $1 }
 | TYPE_CNAME { $1 }
 | TYPE_SOA { $1 }
 | TYPE_MB { $1 }
 | TYPE_MG { $1 }
 | TYPE_MR { $1 }
 | TYPE_NULL { $1 }
 | TYPE_WKS { $1 }
 | TYPE_PTR { $1 }
 | TYPE_HINFO { $1 }
 | TYPE_MINFO { $1 }
 | TYPE_MX { $1 }
 | TYPE_TXT { $1 }
 | TYPE_RP { $1 }
 | TYPE_AFSDB { $1 }
 | TYPE_X25 { $1 }
 | TYPE_ISDN { $1 }
 | TYPE_RT { $1 }
 | TYPE_NSAP { $1 }
 | TYPE_NSAP_PTR { $1 }
 | TYPE_SIG { $1 }
 | TYPE_KEY { $1 }
 | TYPE_PX { $1 }
 | TYPE_GPOS { $1 }
 | TYPE_AAAA { $1 }
 | TYPE_LOC { $1 }
 | TYPE_NXT { $1 }
 | TYPE_EID { $1 }
 | TYPE_NIMLOC { $1 }
 | TYPE_SRV { $1 }
 | TYPE_ATMA { $1 }
 | TYPE_NAPTR { $1 }
 | TYPE_KX { $1 }
 | TYPE_CERT { $1 }
 | TYPE_A6 { $1 }
 | TYPE_DNAME { $1 }
 | TYPE_SINK { $1 }
 | TYPE_OPT { $1 }
 | TYPE_APL { $1 }
 | TYPE_DS { $1 }
 | TYPE_SSHFP { $1 }
 | TYPE_IPSECKEY { $1 }
 | TYPE_RRSIG { $1 }
 | TYPE_NSEC { $1 }
 | TYPE_DNSKEY { $1 }
 | TYPE_SPF { $1 }
 | TYPE_UINFO { $1 }
 | TYPE_UID { $1 }
 | TYPE_GID { $1 }
 /* | TYPE_UNSPEC { $1 } */
 | TYPE_TKEY { $1 }
 | TYPE_TSIG { $1 }
 | TYPE_MAILB { $1 }
 | TYPE_MAILA { $1 }
 | CLASS_IN { $1 }
 | CLASS_CS { $1 }
 | CLASS_CH { $1 }
 | CLASS_HS { $1 }

%%

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
 * dnsquery.ml -- map DNS query-response mechanism onto trie database
 *
 *)

open Operators
open RR
open Trie
open Printf

module H = Hashcons

(* We answer a query with RCODE, AA, ANSWERS, AUTHORITY and ADDITIONAL *)

type answer = {
  rcode : Packet.rcode;
  aa: bool;
  answer: Packet.rr list;
  authority: Packet.rr list;
  additional: Packet.rr list;
}

type filter = Name.t -> RR.rrset -> RR.rrset

type flush = Name.t -> Packet.rdata -> bool

let response_of_answer ?(mdns=false) query answer =
  (*let edns_rec =
    try
    List.find (fun rr -> ) query.additionals
    with Not_found -> []
    in *)
  let detail = {
    Packet.qr=Packet.Response; opcode=Packet.Standard; aa=answer.aa;
    tc=false;
    rd=(if mdns then false else Packet.(query.detail.rd));  (* rfc6762 s18.6_p1_c1 *)
    ra=false; rcode=answer.rcode
  } in
  Packet.({
      id=(if mdns then 0 else query.id);
      detail;
      (* mDNS does not echo questions in the response *)
      questions=(if mdns then [] else query.questions);
      answers=answer.answer;
      authorities=answer.authority;
      additionals=answer.additional;
    })

let answer_of_response ?(preserve_aa=false) ({
  Packet.detail={ Packet.rcode; aa; _ };
  answers; authorities; additionals; _
}) = { rcode; aa = if preserve_aa then aa else false;
       answer=answers;
       authority=authorities;
       additional=additionals;
     }

let create ?(dnssec=false) ~id q_class q_type q_name =
  let open Packet in
  let detail = {
    qr=Query; opcode=Standard;
    aa=false; tc=false; rd=true; ra=false; rcode=NoError;
  } in
  let additionals =
    if dnssec then
      [ ( {
        name=Name.empty; cls=RR_IN; flush=false; ttl=0l;
        rdata=(EDNS0(1500, 0, true, []));} ) ]
    else
      []
  in
  let question = { q_name; q_type; q_class; q_unicast=Q_Normal } in
  { id; detail; questions=[question];
    answers=[]; authorities=[]; additionals;
  }

let null_filter _owner rrset = rrset

let flush_false _owner _rdata = false

let answer_multiple ?(dnssec=false) ?(mdns=false) ?(filter=null_filter) ?(flush=flush_false) questions trie =

  let aa_flag = ref true in
  let ans_rrs = ref [] in
  let auth_rrs = ref [] in
  let add_rrs = ref [] in
  let addqueue = ref [] in
  let rrlog = ref [] in

  (* We must avoid repeating RRSets in the response.  To do this, we
     keep two lists: one of RRSets that are already included, and one of
     RRSets we plan to put in the additional records section.  When we
     add an RRSet to the answer or authority section we strip it from
     the additionals queue, and when we enqueue an additional RRSet we
     make sure it's not already been included.
     N.B. (1) We only log those types that might turn up more than once.
     N.B. (2) We can use "==" and "!=" because owners are unique:
     they are either the owner field of a dnsnode from the
     trie, or they are the qname, which only happens if it
     does not have any RRSets of its own and matched a wildcard.*)
  let log_rrset owner rrtype =
    addqueue :=
      List.filter
      (fun (n, _q, t) -> rrtype != t || owner != n.owner.H.node)
      !addqueue;
    rrlog := (owner, rrtype) :: !rrlog
  in

  let in_log owner rrtype =
    try List.assq owner !rrlog == rrtype
    with Not_found -> false
  in

  let enqueue_additional dnsnode qtype rrtype =
    if not (in_log dnsnode.owner.H.node rrtype )
    then addqueue := (dnsnode, qtype, rrtype) :: !addqueue
  in

  let add_rrset owner ttl rdata section =
    let addrr rr =
      let rr = Packet.({ name = owner;
                         cls = Packet.RR_IN;
                         flush = flush owner rr;
                         ttl = ttl;
                         rdata = rr })
      in
      match section with
        | `Answer     -> ans_rrs  := rr :: !ans_rrs
        | `Authority  -> auth_rrs := rr :: !auth_rrs
        | `Additional -> add_rrs  := rr :: !add_rrs
    in

    (* having extracted record from trie, partially marshal it *)
    match rdata with
      | RR.A l ->
          log_rrset owner Packet.RR_A;
          List.iter (fun ip -> addrr (Packet.A ip)) l

      | RR.AAAA l ->
          log_rrset owner Packet.RR_AAAA;
          List.iter (fun ip -> addrr (Packet.AAAA ip)) l

      | RR.NS l ->
          log_rrset owner Packet.RR_NS;
        List.iter (fun d ->
            enqueue_additional d Packet.Q_A Packet.RR_A;
            enqueue_additional d Packet.Q_AAAA Packet.RR_AAAA;
            addrr (Packet.NS d.owner.H.node)
          ) l

      | RR.CNAME l ->
          List.iter (fun d -> addrr (Packet.CNAME d.owner.H.node)) l

      | RR.SOA l -> log_rrset owner Packet.RR_SOA;
        List.iter (fun (prim,admin,serial,refresh,retry,expiry,minttl) ->
            addrr (Packet.SOA (prim.owner.H.node,
                           admin.owner.H.node,
                               serial, refresh, retry, expiry, minttl))) l

      | RR.MB l ->
        List.iter (fun d ->
          enqueue_additional d Packet.Q_A Packet.RR_A;
          enqueue_additional d Packet.Q_AAAA Packet.RR_AAAA;
          addrr (Packet.MB d.owner.H.node)) l

      | RR.MG l ->
        List.iter (fun d -> addrr (Packet.MG d.owner.H.node)) l

      | RR.MR l ->
        List.iter (fun d -> addrr (Packet.MR d.owner.H.node)) l

      | RR.WKS l ->
        List.iter (fun (address, protocol, bitmap) ->
          addrr (Packet.WKS (address, protocol, bitmap.H.node))) l

      | RR.PTR l ->
        List.iter (
          fun d ->
            if mdns then begin
              (* RFC 6763 section 12.1 *)
              enqueue_additional d Packet.Q_SRV Packet.RR_SRV;
              enqueue_additional d Packet.Q_TXT Packet.RR_TXT;
            end;
            addrr (Packet.PTR d.owner.H.node)
        ) l

      | RR.HINFO l ->
        List.iter (fun (cpu, os) ->
          addrr (Packet.HINFO (cpu.H.node, os.H.node))) l

      | RR.MINFO l ->
        List.iter (fun (rm, em) ->
          addrr (Packet.MINFO (rm.owner.H.node, em.owner.H.node))) l

      | RR.MX l ->
        List.iter (fun (preference, d) ->
          enqueue_additional d Packet.Q_A Packet.RR_A;
          enqueue_additional d Packet.Q_AAAA Packet.RR_AAAA;
          addrr (Packet.MX (preference, d.owner.H.node))) l

      | RR.TXT l ->
        List.iter (fun sl -> (* XXX handle multiple TXT cstrings properly *)
          let data = List.map (fun x -> x.H.node) sl in
            addrr (Packet.TXT data)) l

      | RR.RP l ->
        List.iter (fun (mbox, txt) ->
          addrr (Packet.RP (mbox.owner.H.node, txt.owner.H.node))) l

      | RR.AFSDB l ->
        List.iter (fun (t, d) ->
          enqueue_additional d Packet.Q_A Packet.RR_A;
          enqueue_additional d Packet.Q_AAAA Packet.RR_AAAA;
          addrr (Packet.AFSDB (t, d.owner.H.node))) l

      | RR.X25 l ->
          log_rrset owner Packet.RR_X25;
        List.iter (fun s -> addrr (Packet.X25 s.H.node)) l

      | RR.ISDN l ->
          log_rrset owner Packet.RR_ISDN;
        List.iter (fun (a, sa) ->
            let sa = match sa with None -> None | Some sa -> Some sa.H.node in
            addrr (Packet.ISDN (a.H.node, sa))) l

      (*
        (function (* XXX handle multiple cstrings properly *)
        | (addr, None)
        -> addrr (`ISDN addr.H.node)
        | (addr, Some sa) (* XXX Handle multiple charstrings properly *)
        -> addrr (`ISDN (addr.H.node ^ sa.H.node))) l
      *)

      | RR.RT l ->
        List.iter (fun (preference, d) ->
          enqueue_additional d Packet.Q_A Packet.RR_A;
          enqueue_additional d Packet.Q_AAAA Packet.RR_AAAA;
          enqueue_additional d Packet.Q_X25 Packet.RR_X25;
          enqueue_additional d Packet.Q_ISDN Packet.RR_ISDN;
          addrr (Packet.RT (preference, d.owner.H.node))) l

      | RR.SRV l ->
          List.iter (fun (priority, weight, port, d) ->
          enqueue_additional d Packet.Q_A Packet.RR_A;
          enqueue_additional d Packet.Q_AAAA Packet.RR_AAAA;
          addrr (Packet.SRV (priority, weight, port, d.owner.H.node))) l
      | RR.DS l ->
          List.iter (fun (tag, alg, digest, k) ->
            addrr (Packet.DS (tag, alg, digest, k.H.node) )) l

      (* | RR.UNSPEC l ->  *)
      (*     List.iter (fun s -> addrr (Packet.UNSPEC s.H.node)) l *)

      | RR.DNSKEY l ->
          List.iter (fun  (fl, t, k) ->
            let tt = Packet.int_to_dnssec_alg t in
            match tt with
              | None -> failwith (sprintf "bad dnssec alg type t:%d" t)
              | Some tt -> addrr (Packet.DNSKEY (fl, tt, k.H.node))
          ) l
      | RR.RRSIG l -> begin
        List.iter
          (fun { rrsig_type = typ;
                 rrsig_alg = alg;
                 rrsig_labels = lbl;
                 rrsig_ttl = ttl;
                 rrsig_expiry = exp_ts;
                 rrsig_incept = inc_ts;
                 rrsig_keytag = tag;
                 rrsig_name = name;
                 rrsig_sig = sign;
               } ->
            addrr (Packet.RRSIG (typ, alg, lbl, ttl,
                                 exp_ts, inc_ts, tag,
                                 name, sign)) ) l
        end

      | RR.Unknown (t,l) ->
          let s = l ||> (fun x -> x.H.node) |> String.concat "" in
           addrr (Packet.UNKNOWN (t, s))
  in

  (* Extract relevant RRSets given a query type, a list of RRSets and a flag to
     say whether to return Cnames too *)
  let get_rrsets qtype sets cnames_ok =
    let some_rrset set =
      (* eprintf "MATCH q:%s r:%s\n%!"  *)
      (*   (Packet.q_type_to_string qtype) (RR.rdata_to_string set.rdata); *)
      (* TODO: where does this map belong? *)
      match (qtype, set.rdata) with
        | (Packet.Q_A,      A _)
        | (Packet.Q_NS,     NS _)
        | (Packet.Q_CNAME,  CNAME _)
        | (Packet.Q_SOA,    SOA _)
        | (Packet.Q_MB,     MB _)
        | (Packet.Q_MG,     MG _)
        | (Packet.Q_MR,     MR _)
        | (Packet.Q_WKS,    WKS _)
        | (Packet.Q_PTR,    PTR _)
        | (Packet.Q_HINFO,  HINFO _)
        | (Packet.Q_MINFO,  MINFO _)
        | (Packet.Q_MX,     MX _)
        | (Packet.Q_TXT,    TXT _)
        | (Packet.Q_RP,     RP _)
        | (Packet.Q_AFSDB,  AFSDB _)
        | (Packet.Q_X25,    X25 _)
        | (Packet.Q_ISDN,   ISDN _)
        | (Packet.Q_RT,     RT _)
        | (Packet.Q_SRV,    SRV _)
        | (Packet.Q_AAAA,   AAAA _)
        | (Packet.Q_DS,     DS _)
        | (Packet.Q_DNSKEY, DNSKEY _)
        | (Packet.Q_RRSIG,  RRSIG _)
        (* | (Packet.Q_UNSPEC, UNSPEC _) -> true *)
        | (Packet.Q_MAILB,  MB _)
        | (Packet.Q_MAILB,  MG _)
        | (Packet.Q_MAILB,  MR _)
        | (Packet.Q_ANY_TYP,_) -> Some set
        | (_, CNAME _) when cnames_ok -> Some set
        | (_, RRSIG rrsigl) when dnssec ->
          Some ({ set with rdata =
              RRSIG (List.filter
                       (fun {rrsig_type; _} ->
                         Packet.q_type_matches_rr_type qtype rrsig_type)
                       rrsigl)
                })
        | (_, _) -> None
    in List.fold_right (fun set sets ->
        match some_rrset set with
        | Some set -> set::sets
        | _ -> sets
    ) sets []
  in

  (* Get an RRSet, which may not exist *)
  let add_opt_rrset node qtype rrtype section =
    if not (in_log node.owner.H.node rrtype )
    then
      let a = get_rrsets qtype node.rrsets false in
      List.iter (fun s ->
        add_rrset node.owner.H.node s.ttl s.rdata section) a
  in

  (* Get an RRSet, which must exist *)
  let add_req_rrset node qtype rrtype section =
    if not (in_log node.owner.H.node rrtype)
    then
      let a = get_rrsets qtype node.rrsets false in
      if a = [] then raise TrieCorrupt;
      List.iter (fun s ->
        add_rrset node.owner.H.node s.ttl s.rdata section) a
  in

  (* Get the SOA RRSet for a negative response *)
  let add_negative_soa_rrset =
    if mdns then fun _node -> ()
    else fun node ->
    (* Don't need to check if it's already there *)
    let a = get_rrsets Packet.Q_SOA node.rrsets false in
    if a = [] then raise TrieCorrupt;
    (* RFC 2308: The TTL of the SOA RRset in a negative response must be set
       to the minimum of its own TTL and the "minimum" field of the SOA
       itself *)
    List.iter (fun s ->
      match s.rdata with
        SOA ((_, _, _, _, _, _, ttl) :: _) ->
          add_rrset node.owner.H.node (min s.ttl ttl)
           s.rdata `Authority
        | _ -> raise TrieCorrupt ) a
  in

  (* Fill in the ANSWER section *)
  let rec add_answer_rrsets owner ?(lc = 5) rrsets qtype =
    let add_answer_rrset s =
      match s with
        | { rdata = CNAME (d::_); _ } ->
            (* Only follow the first CNAME in a set *)
          if not (lc < 1 || qtype = Packet.Q_CNAME ) then begin
              add_answer_rrsets d.owner.H.node ~lc:(lc - 1) d.rrsets qtype
            end;
          add_rrset owner s.ttl s.rdata `Answer
        | _ -> add_rrset owner s.ttl s.rdata `Answer
    in
    let a = get_rrsets qtype rrsets true in
    let f1 = List.map (filter owner) a in
    let f2 = List.filter (fun rrset -> rrset.RR.ttl <> 0l) f1 in
    List.iter add_answer_rrset f2
  in

  (* Call the trie lookup and assemble the RRs for a response *)
  let main_lookup qname qtype trie =
    let key = Name.to_key qname in
    match lookup key trie ~mdns with
      | `Found (_sec, node, zonehead) -> (* Name has RRs, and we own it. *)
        add_answer_rrsets node.owner.H.node node.rrsets qtype;
        add_opt_rrset zonehead Packet.Q_NS Packet.RR_NS `Authority;
        Packet.NoError

      | `NoError (zonehead) ->          (* Name "exists", but has no RRs. *)
        add_negative_soa_rrset zonehead;
        Packet.NoError

      | `NoErrorNSEC (zonehead, _nsec) ->
        add_negative_soa_rrset zonehead;
        (* add_opt_rrset nsec `NSEC `Authority; *)
        Packet.NoError

      | `Delegated (_sec, cutpoint) ->   (* Name is delegated. *)
        add_req_rrset cutpoint Packet.Q_NS Packet.RR_NS `Authority;
        aa_flag := false;
        (* DNSSEC child zone keys *)
        Packet.NoError

      | `Wildcard (source, zonehead) -> (* Name is matched by a wildcard. *)
        add_answer_rrsets qname source.rrsets qtype;
        add_opt_rrset zonehead Packet.Q_NS Packet.RR_NS `Authority;
        Packet.NoError

      | `WildcardNSEC (source, zonehead, _nsec) ->
        add_answer_rrsets qname source.rrsets qtype;
        add_opt_rrset zonehead Packet.Q_NS Packet.RR_NS `Authority;
        (* add_opt_rrset nsec `NSEC `Authority; *)
        Packet.NoError

      | `NXDomain (zonehead) ->         (* Name doesn't exist. *)
        add_negative_soa_rrset zonehead;
        Packet.NXDomain

      | `NXDomainNSEC (zonehead, _nsec1, _nsec2) ->
        add_negative_soa_rrset zonehead;
        (* add_opt_rrset nsec1 `NSEC `Authority; *)
        (* add_opt_rrset nsec2 `NSEC `Authority; *)
        Packet.NXDomain
  in

  let rec lookup_multiple qs trie rc =
    let open Packet in
    match qs with
    | [] -> rc
    | hd::tl ->
      let next_rc =
        (* main_lookup only supports RR_IN *)
        match hd.q_class with
        | Q_IN
        | Q_ANY_CLS -> main_lookup hd.q_name hd.q_type trie
        | Q_CS
        | Q_CH
        | Q_HS
        | Q_NONE -> NXDomain
      in
      match next_rc with
      (* If all questions result in NXDomain then return NXDomain,
         or if any question results in another kind of error then abort,
         else return NoError *)
      | NoError -> lookup_multiple tl trie NoError
      | NXDomain -> lookup_multiple tl trie rc
      | _ -> next_rc
  in

  try
    let rc = lookup_multiple questions trie Packet.NXDomain in
    List.iter (fun (o, q, t) ->
      add_opt_rrset o q t `Additional) !addqueue;
    let _ =
      if (dnssec) then
      let rr = Packet.({ name = Name.empty; cls = RR_IN; flush = false;
                         ttl = 0x00008000l;
                         rdata = EDNS0(1500, 0, true, [])})
      in
        add_rrs := !add_rrs @ [(rr)]
    in
    { rcode = rc; aa = !aa_flag;
      answer = !ans_rrs; authority = !auth_rrs; additional = !add_rrs }
  with
  | Name.BadDomainName _ -> {
    rcode = Packet.FormErr; aa = false;
    answer = []; authority = []; additional=[];
  }
  | TrieCorrupt -> {
    rcode = Packet.ServFail; aa = false;
    answer = []; authority = []; additional=[];
  }

let answer ?(dnssec=false) ?(mdns=false) ?(filter=null_filter) ?flush:_ qname qtype trie =
  answer_multiple ~dnssec ~mdns ~filter
    [{Packet.q_name=qname; Packet.q_type=qtype; Packet.q_class=Packet.Q_IN; Packet.q_unicast=Packet.Q_Normal}]
    trie

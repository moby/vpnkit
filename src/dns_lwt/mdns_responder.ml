(*
 * Copyright (c) 2015 Luke Dunstan <LukeDunstan81@gmail.com>
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

open Lwt.Infix

module DR = Dns.RR
module DP = Dns.Packet
module DS = Dns.Protocol.Server
module DQ = Dns.Query
module H = Hashcons
module Probe = Dns.Probe

type ip_endpoint = Ipaddr.V4.t * int

module type TRANSPORT = sig
  val alloc : unit -> Cstruct.t
  val write : ip_endpoint -> Cstruct.t -> unit Lwt.t
  val sleep : float -> unit Lwt.t
end

let label str =
  MProf.Trace.label ("Mdns_responder:" ^ str)

let multicast_ip = Ipaddr.V4.of_string_exn "224.0.0.251"

let sentinel = DR.Unknown (0, [])

let filter_out_known rr known =
  match (rr, known) with

  | (DR.A l, DP.A k) ->
    let lf = List.filter (fun ip -> k <> ip) l
    in
    if lf <> [] then DR.A lf else sentinel

  | (DR.AAAA l, DP.AAAA k) ->
    let lf = List.filter (fun ip -> k <> ip) l
    in
    if lf <> [] then DR.AAAA lf else sentinel

  | (DR.CNAME l, DP.CNAME k) ->
    let lf = List.filter (fun d -> d.DR.owner.H.node <> k) l
    in
    if lf <> [] then DR.CNAME lf else sentinel

  | (DR.MB l, DP.MB k) ->
    let lf = List.filter (fun d -> d.DR.owner.H.node <> k) l
    in
    if lf <> [] then DR.MB lf else sentinel

  | (DR.MG l, DP.MB k) ->
    let lf = List.filter (fun d -> d.DR.owner.H.node <> k) l
    in
    if lf <> [] then DR.MG lf else sentinel

  | (DR.MR l, DP.MR k) ->
    let lf = List.filter (fun d -> d.DR.owner.H.node <> k) l
    in
    if lf <> [] then DR.MR lf else sentinel

  | (DR.NS l, DP.NS k) ->
    let lf = List.filter (fun d -> d.DR.owner.H.node <> k) l
    in
    if lf <> [] then DR.NS lf else sentinel

  (* SOA not relevant *)
  | (DR.WKS l, DP.WKS (ka, kp, kb)) ->
    let lf = List.filter (fun (address, protocol, bitmap) ->
        address <> ka || protocol <> kp || bitmap.H.node <> kb) l
    in
    if lf <> [] then DR.WKS lf else sentinel

  | (DR.PTR l, DP.PTR k) ->
    let lf = List.filter (fun d -> d.DR.owner.H.node <> k) l
    in
    if lf <> [] then DR.PTR lf else sentinel

  | (DR.HINFO l, DP.HINFO (kcpu, kos)) ->
    let lf = List.filter (fun (cpu, os) -> cpu.H.node <> kcpu || os.H.node <> kos) l
    in
    if lf <> [] then DR.HINFO lf else sentinel

  | (DR.MINFO l, DP.MINFO (krm, kem)) ->
    let lf = List.filter (fun (rm, em) -> rm.DR.owner.H.node <> krm || em.DR.owner.H.node <> kem) l
    in
    if lf <> [] then DR.MINFO lf else sentinel

  | (DR.MX l, DP.MX (kp, kn)) ->
    let lf = List.filter (fun (preference, d) -> preference <> kp || d.DR.owner.H.node <> kn) l
    in
    if lf <> [] then DR.MX lf else sentinel

  | (DR.TXT _ll, DP.TXT _kl) ->
    sentinel  (* TODO *)

  | (DR.RP l, DP.RP (kmbox, ktxt)) ->
    let lf = List.filter (fun (mbox, txt) -> mbox.DR.owner.H.node <> kmbox || txt.DR.owner.H.node <> ktxt) l
    in
    if lf <> [] then DR.RP lf else sentinel

  | (DR.AFSDB l, DP.AFSDB (kt, kn)) ->
    let lf = List.filter (fun (t, d) -> t <> kt || d.DR.owner.H.node <> kn) l
    in
    if lf <> [] then DR.AFSDB lf else sentinel

  | (DR.X25 l, DP.X25 k) ->
    let lf = List.filter (fun s -> s.H.node <> k) l
    in
    if lf <> [] then DR.X25 lf else sentinel

  | (DR.ISDN l, DP.ISDN (ka, ksa)) ->
    let lf = List.filter (fun (a, sa) ->
        let sa = match sa with None -> None | Some sa -> Some sa.H.node in
        a.H.node <> ka || sa <> ksa) l
    in
    if lf <> [] then DR.ISDN lf else sentinel

  | (DR.RT l, DP.RT (kp, kn)) ->
    let lf = List.filter (fun (preference, d) -> preference <> kp || d.DR.owner.H.node <> kn) l
    in
    if lf <> [] then DR.RT lf else sentinel

  | (DR.SRV l, DP.SRV (kprio, kw, kport, kn)) ->
    let lf = List.filter (fun (priority, weight, port, d) ->
        priority <> kprio || weight <> kw || port <> kport || d.DR.owner.H.node <> kn) l
    in
    if lf <> [] then DR.SRV lf else sentinel

  | (DR.DS l, DP.DS (kt, ka, kd, kn)) ->
    let lf = List.filter (fun (tag, alg, digest, k) ->
        tag <> kt || alg <> ka || digest <> kd || k.H.node <> kn) l
    in
    if lf <> [] then DR.DS lf else sentinel

  | (DR.DNSKEY l, DP.DNSKEY (kfl, ktt, kk)) ->
    let lf = List.filter (fun (fl, t, k) ->
        let tt = DP.int_to_dnssec_alg t in
        match tt with
        | None -> false
        | Some tt -> fl <> kfl || tt <> ktt || k.H.node <> kk
      ) l
    in
    if lf <> [] then DR.DNSKEY lf else sentinel

  | (DR.RRSIG l, DP.RRSIG (ktyp, kalg, klbl, kttl, kexp_ts, kinc_ts, ktag, kname, ksign)) ->
    let lf = List.filter DR.(fun {
        rrsig_type = typ;
        rrsig_alg = alg;
        rrsig_labels = lbl;
        rrsig_ttl = ttl;
        rrsig_expiry = exp_ts;
        rrsig_incept = inc_ts;
        rrsig_keytag = tag;
        rrsig_name = name;
        rrsig_sig = sign;
      } ->
        typ <> ktyp || alg <> kalg || lbl <> klbl || ttl <> kttl ||
        exp_ts <> kexp_ts || inc_ts <> kinc_ts || tag <> ktag ||
        name <> kname || sign <> ksign
      ) l
    in
    if lf <> [] then DR.RRSIG lf else sentinel

  | (DR.Unknown _, _) -> sentinel

  | _, _ -> rr

let rec filter_known_list rr knownl =
  match knownl with
  | [] -> rr
  | known::tl ->
    begin
      let frr = filter_out_known rr known.DP.rdata in
      match frr with DR.Unknown _ -> frr | _ -> filter_known_list frr tl
    end


module Make (Transport : TRANSPORT) = struct

  type t = {
    db : Dns.Loader.db;
    dnstrie : Dns.Trie.dnstrie;
    probe_condition : unit Lwt_condition.t;
    mutable probe_forever : unit Lwt.t;
    mutable probe : Probe.state;
  }


  let of_db db =
    let dnstrie = db.Dns.Loader.trie in
    {
      db; dnstrie;
      probe_condition = Lwt_condition.create ();
      probe_forever=Lwt.return_unit;
      probe = Probe.new_state db;
    }

  let of_zonebufs zonebufs =
    let db = List.fold_left (fun db -> Dns.Zone.load ~db [])
        (Dns.Loader.new_db ()) zonebufs in
    of_db db

  let of_zonebuf zonebuf = of_zonebufs [zonebuf]


  let add_unique_hostname t name ?(ttl=120_l) ip =
    (* TODO: support IPv6 with AAAA *)
    (* Add it to the trie *)
    Dns.Loader.add_a_rr ip ttl name t.db;
    (* Add an entry to our own table of unique records *)
    t.probe <- Probe.add_name t.probe name

  (* This predicate controls the cache-flush bit *)
  let is_confirmed_unique t owner _rdata =
    Probe.is_confirmed t.probe owner

  let rec probe_forever t action first first_wakener =
    let send_action packet ip port =
      match Dns.Protocol.contain_exc "marshal" (fun () -> DP.marshal ~alloc:Transport.alloc packet) with
      | None -> Lwt.return_unit
      | Some buf -> Transport.write (ip, port) buf
    in

    match action with
    | Probe.Nothing ->
      label "Nothing";
      if (Probe.is_first_complete t.probe) && !first then begin
        (* Only once, because a thread can only be woken once *)
        first := false;
        Lwt.wakeup first_wakener ()
      end;
      Lwt_condition.wait t.probe_condition >>= fun () ->
      probe_forever t Probe.Continue first first_wakener

    | Probe.ToSend (packet, ip, port) ->
      label "ToSend";
      (* t.probe is also modified in process_response *)
      send_action packet ip port >>= fun () ->
      let state, next_action = Probe.on_send_complete t.probe in
      t.probe <- state;
      probe_forever t next_action first first_wakener

    | Probe.Delay delay ->
      label "Delay";
      (* The condition allows the sleep to be interrupted *)
      (* t.probe is also modified in process_response *)
      Lwt.pick [
        Transport.sleep delay;
        Lwt_condition.wait t.probe_condition
      ] >>= fun () ->
      let state, next_action = Probe.on_delay_complete t.probe in
      t.probe <- state;
      probe_forever t next_action first first_wakener

    | Probe.Continue ->
      label "Continue";
      let state, next_action = Probe.do_probe t.probe in
      t.probe <- state;
      probe_forever t next_action first first_wakener

    | Probe.NotReady ->
      label "NotReady";
      (* This is a bug. There's not much we can do but return. *)
      Lwt.return_unit

    | Probe.Stop ->
      label "Stop";
      Lwt.return_unit

  let first_probe t =
    label "first_probe";
    (* Random delay of 0-250 ms *)
    Transport.sleep (Random.float 0.25) >>= fun () ->
    let first = ref true in
    let first_wait, first_wakener = Lwt.wait () in
    t.probe_forever <- probe_forever t Probe.Continue first first_wakener;
    (* The caller may wait for the first complete probe cycle *)
    first_wait

  let announce t ~repeat =
    label "announce";
    let questions = ref [] in
    let build_questions node =
      let q = DP.({
        q_name = node.DR.owner.H.node;
        q_type = Q_ANY_TYP;
        q_class = Q_IN;
        q_unicast = Q_Normal;
      }) in
      questions := q :: !questions
    in
    let dedup_answer answer =
      (* Delete duplicate RRs from the response *)
      (* FIXME: O(N*N) *)
      (* TODO: Dns.Query shouldn't generate duplicate RRs *)
      let rr_eq rr1 rr2 =
        rr1.DP.name = rr2.DP.name &&
        DP.compare_rdata rr1.DP.rdata rr2.DP.rdata = 0
      in
      let rec dedup l =
        match l with
        | [] -> l
        | hd::tl -> if List.exists (rr_eq hd) tl
          then tl
          else hd :: dedup tl
      in
      { answer with DQ.answer = dedup answer.DQ.answer; DQ.additional = [] }
    in
    let rec write_repeat dest obuf repeat sleept =
      (* RFC 6762 section 11 - TODO: send with IP TTL = 255 *)
      Transport.write dest obuf >>= fun () ->
      if repeat = 1 then
        Lwt.return_unit
      else
        Transport.sleep sleept >>= fun () ->
        write_repeat dest obuf (repeat - 1) (sleept *. 2.0)
    in
    Dns.Trie.iter build_questions t.dnstrie;
    (* TODO: if the data for a shared record has changed, we should send 'goodbye'.
       See RFC 6762 section 8.4 *)
    let answer = DQ.answer_multiple ~dnssec:false ~mdns:true ~flush:(is_confirmed_unique t) !questions t.dnstrie in
    let answer = dedup_answer answer in
    let dest_host = multicast_ip in
    let dest_port = 5353 in
    (* TODO: refactor Dns.Query to avoid the need for this fake query *)
    let fake_detail = DP.({ qr=Query; opcode=Standard; aa=false; tc=false; rd=false; ra=false; rcode=NoError}) in
    let fake_query = DP.({
        id=0;
        detail=fake_detail;
        questions= !questions; answers=[]; authorities=[]; additionals=[];
    }) in
    let response = DQ.response_of_answer ~mdns:true fake_query answer in
    if response.DP.answers = [] then
      Lwt.return_unit
    else
      (* TODO: limit the response packet size *)
      match DS.marshal ~alloc:Transport.alloc fake_query response with
      | None -> Lwt.return_unit
      | Some obuf -> write_repeat (dest_host,dest_port) obuf repeat 1.0


  let get_answer t query =
    let filter name rrset =
      (* RFC 6762 section 7.1 - Known Answer Suppression *)
      (* First match on owner name and check TTL *)
      let relevant_known = List.filter (fun known ->
          (name = known.DP.name) && (known.DP.ttl >= Int32.div rrset.DR.ttl 2l)
        ) query.DP.answers
      in
      (* Now suppress known records based on RR type *)
      let rdata = filter_known_list rrset.DR.rdata relevant_known in
      {
        DR.ttl = (match rdata with DR.Unknown _ -> 0l | _ -> rrset.DR.ttl);
        DR.rdata = rdata;
      }
    in
    (* DNSSEC disabled for testing *)
    DQ.answer_multiple ~dnssec:false ~mdns:true ~filter ~flush:(is_confirmed_unique t) query.DP.questions t.dnstrie

  let process_query t src _dst query =
    let get_delay legacy response =
      if legacy then
        (* No delay for legacy mode *)
        Lwt.return_unit
      else if List.exists (fun a -> a.DP.flush) response.DP.answers then
        (* No delay for records that have been verified as unique *)
        (* TODO: send separate unique and non-unique responses if applicable *)
        Lwt.return_unit
      else
        (* Delay response for 20-120 ms *)
        Transport.sleep (0.02 +. Random.float 0.1)
    in
    (* rfc6762 s6.7_p2_c1 - legacy TTL must be <= 10 sec *)
    let limit_rrs_ttl ~limit rrs =
      List.map (fun rr -> { rr with DP.ttl = (min rr.DP.ttl limit) }) rrs
    in
    let limit_answer_ttl ~limit answer =
      { answer with
        DQ.answer = limit_rrs_ttl ~limit answer.DQ.answer;
        DQ.authority = limit_rrs_ttl ~limit answer.DQ.authority;
        DQ.additional = limit_rrs_ttl ~limit answer.DQ.additional;
      }
    in
    match Dns.Protocol.contain_exc "answer" (fun () -> get_answer t query) with
    | None -> Lwt.return_unit
    | Some answer when answer.DQ.answer = [] -> Lwt.return_unit
    | Some answer ->
      let src_host, src_port = src in
      let legacy = (src_port != 5353) in
      let unicast =
        (* True if all of the questions have the unicast response bit set *)
        (* TODO: split into separate unicast and multicast responses if applicable *)
        if legacy then
          false
        else
          List.for_all (fun q -> q.DP.q_unicast = DP.Q_mDNS_Unicast) query.DP.questions
      in
      let reply_host = if legacy || unicast then src_host else multicast_ip in
      let reply_port = src_port in
      (* rfc6762 s6.7_p2_c1 - legacy TTL must be <= 10 sec *)
      let answer = if legacy then limit_answer_ttl ~limit:10_l answer else answer in
      (* RFC 6762 section 18.5 - TODO: check tc bit *)
      (* NOTE: echoing of questions is still required for legacy mode *)
      let response = DQ.response_of_answer ~mdns:(not legacy) query answer in
      let response, new_state, conflict = Probe.on_query_received t.probe query response in
      t.probe <- new_state;
      if conflict = Probe.ConflictRestart then
        Lwt_condition.signal t.probe_condition ();
      if response.DP.answers = [] then
        Lwt.return_unit
      else
        begin
          (* Possible delay before responding *)
          get_delay legacy response >>= fun () ->
          (* TODO: limit the response packet size *)
          match DS.marshal ~alloc:Transport.alloc query response with
          | None -> Lwt.return_unit
          | Some obuf ->
            (* RFC 6762 section 11 - TODO: send with IP TTL = 255 *)
            Transport.write (reply_host,reply_port) obuf
        end


  let process_response t response =
    let state, conflict = Probe.on_response_received t.probe response in
    t.probe <- state;
    if conflict = Probe.ConflictRestart then
      Lwt_condition.signal t.probe_condition ();
    (* RFC 6762 section 10.5 - TODO: passive observation of failures *)
    Lwt.return_unit

  let process t ~src ~dst ibuf =
    label "mDNS process";
    let open DP in
    match DS.parse ibuf with
    | None -> Lwt.return_unit
    | Some dp when dp.detail.opcode != Standard ->
      (* RFC 6762 section 18.3 *)
      Lwt.return_unit
    | Some dp when dp.detail.rcode != NoError ->
      (* RFC 6762 section 18.11 *)
      Lwt.return_unit
    | Some dp when dp.detail.qr = Query -> process_query t src dst dp
    | Some dp -> process_response t dp

  let stop_probe t =
    (* TODO: send 'goodbye' for all names *)
    t.probe <- Probe.stop t.probe;
    Lwt_condition.signal t.probe_condition ();
    t.probe_forever

  let trie t = t.dnstrie

end

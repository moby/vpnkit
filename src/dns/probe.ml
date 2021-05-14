(*
   Inputs:
   - Loader.db (for creating probes, etc.)
   - Names of unique RRs
   - Received packets
   - Event: application initiates first probe
   - Event: delay complete
   - Event: send complete
   - (To Do: send fail or network down? trie changed?)

   Outputs (actions):
   - Packets to be sent
   - Delay time
   - Idle/finished indications
*)

let multicast_dns_ip = Ipaddr.V4.of_string_exn "224.0.0.251"
type datagram = Packet.t * Ipaddr.V4.t * int

(* RFC 6762 section 10.2 implies that uniqueness is based on name/rrtype/rrclass,
   but section 8.1 implies that a domain name is enough. *)

module UniqueSet = Name.Set

type probe_number = FirstProbe | SecondProbe | ThirdProbe

type probing_state = {
  datagram : datagram;
  num : probe_number;
  rrs : Packet.rr list;
}

type restart_after = AfterSend | AfterDelay | DoProbe

type probe_stage =
  | ProbeIdle
  | SendingProbe of probing_state
  | DelayAfterSendingProbe of probing_state
  | NeedRestart of restart_after * float
  | DelayBeforeRestart
  | ProbeStopped

type state = {
  stage : probe_stage;
  first_done : bool;
  db : Loader.db;   (* mutable *)
  (* Three lists of unique names *)
  names_pending : UniqueSet.t;
  names_probing : UniqueSet.t;
  names_confirmed : UniqueSet.t;
}

type action =
  | Nothing
  | ToSend of datagram
  | Delay of float
  | Continue
  | NotReady
  | Stop

let new_state db =
  {
    stage = ProbeIdle;
    first_done = false;
    db;
    names_pending = UniqueSet.empty;
    names_probing = UniqueSet.empty;
    names_confirmed = UniqueSet.empty;
  }

(* May call do_probe after this *)
let add_name state name =
  { state with names_pending = UniqueSet.add name state.names_pending }

(* This predicate controls the cache-flush bit *)
let is_confirmed state name =
  UniqueSet.mem name state.names_confirmed

let stop state =
  { state with stage = ProbeStopped }

let is_first_complete state = state.first_done

let prepare_probe names db =
  (* Build a list of questions *)
  let questions = List.map (fun name -> Packet.({
      q_name = name;
      q_type = Q_ANY_TYP;
      q_class = Q_IN;
      q_unicast = Q_mDNS_Unicast;  (* request unicast response as per RFC 6762 section 8.1 para 6 *)
    })) names
  in
  (* Reuse Query.answer_multiple to get the records that we need for the authority section *)
  let answer = Query.answer_multiple ~dnssec:false ~mdns:true questions db.Loader.trie in
  let rrs = List.filter (fun answer -> List.mem answer.Packet.name names) answer.Query.answer in
  if rrs = [] then
    (* There are no unique records to probe for *)
    None
  else
    (* I don't know whether the cache flush bit needs to be set in the authority RRs, but seems logical *)
    let authorities = List.map (fun rr -> { rr with Packet.flush = true }) rrs in
    let detail = Packet.({ qr=Query; opcode=Standard; aa=false; tc=false; rd=false; ra=false; rcode=NoError; }) in
    let query = Packet.({ id=0; detail; questions; answers=[]; authorities; additionals=[]; }) in
    Some (query, rrs)

(* Initiates the first probe *)
let do_probe state =
  let begin_probe () =
    match prepare_probe (UniqueSet.elements state.names_pending) state.db with
    | None ->
      (* Nothing to do right now *)
      ({ state with stage = ProbeIdle }, Nothing)
    | Some (packet, rrs) ->
      (* Send the probe *)
      (* TODO: probes should be per-link if there are multiple NICs *)
      let datagram = (packet,multicast_dns_ip,5353) in
      ({
        state with
        stage = SendingProbe { datagram; num=FirstProbe; rrs };
        names_pending = UniqueSet.empty;
        names_probing = state.names_pending;
      }, ToSend datagram)
  in
  match state.stage with
  | ProbeIdle ->
    begin_probe ()
  | NeedRestart (DoProbe, delay) ->
    if delay = 0.0 then
      begin_probe ()
    else
      ({ state with stage = DelayBeforeRestart }, Delay delay)
  | SendingProbe _
  | DelayAfterSendingProbe _
  | NeedRestart (AfterSend, _)
  | NeedRestart (AfterDelay, _)
  | DelayBeforeRestart ->
    (state, NotReady)
  | ProbeStopped ->
    (state, Stop)

let restart_later state delay =
  match state.stage with
  | SendingProbe _ ->
    { state with stage = NeedRestart (AfterSend, delay) }
  | DelayAfterSendingProbe _ ->
    (* Delays a bit longer than needed *)
    { state with stage = NeedRestart (AfterDelay, delay) }
  | ProbeIdle ->
    { state with stage = NeedRestart (DoProbe, delay) }
  | NeedRestart _
  | DelayBeforeRestart
  | ProbeStopped ->
    (* No change *)
    state

let on_send_complete state =
  match state.stage with
  | SendingProbe probing ->
    (* Fixed delay of 250 ms *)
    ({ state with stage = DelayAfterSendingProbe probing }, Delay 0.25)
    (* Continues in on_delay_complete *)
  | NeedRestart (AfterSend, delay) ->
    ({ state with stage = NeedRestart (DoProbe, delay) }, Continue)
  | DelayAfterSendingProbe _
  | ProbeIdle
  | NeedRestart (AfterDelay, _)
  | NeedRestart (DoProbe, _)
  | DelayBeforeRestart ->
    (* Unexpected event *)
    (state, NotReady)
  | ProbeStopped ->
    (state, Stop)

let on_delay_complete state =
  let after_delay state probing =
    match probing.num with
    | FirstProbe ->
      ({ state with stage = SendingProbe { probing with num = SecondProbe } }, ToSend probing.datagram)
      (* Wait for on_send_complete *)
    | SecondProbe ->
      ({ state with stage = SendingProbe { probing with num = ThirdProbe } }, ToSend probing.datagram)
      (* Wait for on_send_complete *)
    | ThirdProbe ->
      ({
        state with
        stage = ProbeIdle;
        first_done = true;
        names_probing = UniqueSet.empty;
        names_confirmed = UniqueSet.union state.names_confirmed state.names_probing;
      }, Continue)  (* Call do_probe in case state.names_pending is not empty. *)
  in
  match state.stage with
  | DelayAfterSendingProbe probing ->
    after_delay state probing
  | NeedRestart (AfterDelay, delay) ->
    ({ state with stage = NeedRestart (DoProbe, delay) }, Continue)
  | DelayBeforeRestart ->
    do_probe { state with stage = ProbeIdle }
  | ProbeIdle
  | SendingProbe _
  | NeedRestart (AfterSend, _)
  | NeedRestart (DoProbe, _) ->
    (* Unexpected event *)
    (state, NotReady)
  | ProbeStopped ->
    (state, Stop)

(* FIXME: db is mutable *)
let rename_unique state old_name =
  let increment_name name =
    match Name.to_string_list name with
    | head :: tail ->
      let re = Re.Str.regexp "\\(.*\\)\\([0-9]+\\)" in
      let new_head = if Re.Str.string_match re head 0 then begin
          let num = int_of_string (Re.Str.matched_group 2 head) in
          (Re.Str.matched_group 1 head) ^ (string_of_int (num + 1))
        end else
          head ^ "2"
      in
      Name.of_string_list (new_head :: tail)
    | [] -> failwith "can't offer the DNS root"
  in
  (* Find the old RR from the trie *)
  let rrsets =
    match Trie.simple_lookup (Name.to_key old_name) state.db.Loader.trie with
    | None -> failwith "rename_unique: old name not found"
    | Some node ->
      let rrsets = node.RR.rrsets in
      (* Remove the rrsets from the old node *)
      (* TODO: remove the node itself *)
      node.RR.rrsets <- [];
      rrsets
  in
  (* Create a new name *)
  let new_name = increment_name old_name in
  (* Add the new RR to the trie *)
  (* TODO: Loader doesn't support a simple rename operation *)
  List.iter (fun rrset ->
      match rrset.RR.rdata with
      | RR.A l -> List.iter (fun ip -> Loader.add_a_rr ip rrset.RR.ttl new_name state.db) l
      | _ -> failwith "Only A records are supported"
    ) rrsets;
  new_name

type conflict = NoConflict | ConflictRestart

let on_response_received state response =
  (* Check for conflicts *)
  let probing_rrs =
    match state.stage with
    | SendingProbe probing -> probing.rrs
    | DelayAfterSendingProbe probing -> probing.rrs
    | ProbeIdle
    | NeedRestart _
    | DelayBeforeRestart
    | ProbeStopped -> []
  in
  let set_of_list l = List.fold_left (fun s e -> UniqueSet.add e s) UniqueSet.empty l in
  (* RFC 6762 section 9 - need to check all sections *)
  let response_rrs = List.flatten [response.Packet.answers; response.Packet.authorities; response.Packet.additionals] in
  (* Identical records do not count as conflicts, so ignore those *)
  let non_identical = List.filter (fun rr ->
      not (List.exists (fun our ->
          our.Packet.name = rr.Packet.name && Packet.compare_rdata rr.Packet.rdata our.Packet.rdata = 0
        ) probing_rrs)
    ) response_rrs in
  let response_names = List.map (fun rr -> rr.Packet.name) non_identical |> set_of_list in
  (* There was a probe conflict: defer to the existing host *)
  let renamed = UniqueSet.inter response_names state.names_probing in
  let not_renamed = UniqueSet.diff state.names_probing renamed in
  (* Rename the conflicting records *)
  let new_names = UniqueSet.fold (fun name set ->
      (* Modifies the trie! *)
      UniqueSet.add (rename_unique state name) set
    ) renamed UniqueSet.empty
  in
  (* There could also be conflicts with names that we already confirmed as unique,
     in which case we also have to re-probe. *)
  let other_conflicts = UniqueSet.inter response_names state.names_confirmed in
  if UniqueSet.is_empty renamed && UniqueSet.is_empty other_conflicts then
    (* No conflicts *)
    (state, NoConflict)
  else begin
    (* At least one conflict *)
    let now_pending = UniqueSet.union not_renamed new_names in
    (restart_later {
        state with
        (* Reset probing names back to pending *)
        names_pending = UniqueSet.union state.names_pending now_pending;
        names_probing = UniqueSet.empty;
      } 0.0, ConflictRestart)
  end

let on_query_received state query response =
  (* A "simultaneous probe conflict" occurs if we see a (probe) request
     that contains a question matching one of our unique records,
     and the authority section contains different data. *)
  let theirs = List.filter (fun rr -> UniqueSet.mem rr.Packet.name state.names_probing) query.Packet.authorities in
  let result = List.fold_left (fun result auth ->
      match result with
      | ConflictRestart -> result
      | NoConflict ->
        try
          (* For this step we only care about records that are part of the current probe cycle. *)
          let our_rr = List.find (fun rr -> UniqueSet.mem rr.Packet.name state.names_probing) response.Packet.answers in
          (* TODO: proper lexicographical comparison *)
          let compare = Packet.compare_rdata our_rr.Packet.rdata auth.Packet.rdata in
          if compare < 0 then
            (* Our data is less than the requester's data, so restart the probe sequence *)
            ConflictRestart
          else
            NoConflict
        (* else if compare > 0 then the requester will restart its own probe sequence *)
        (* else if compare = 0 then there is no conflict *)
        (* TODO: if compare = 0 and the peer is sending a TTL less than half of our record
           then we are supposed to announce our record to avoid premature expiry *)
        with
        | Not_found -> NoConflict
    ) NoConflict theirs
  in
  (* Now filter out answers that are unique but unconfirmed *)
  let answers = List.filter (fun rr ->
      not (UniqueSet.mem rr.Packet.name state.names_pending) && not (UniqueSet.mem rr.Packet.name state.names_probing)
    ) response.Packet.answers in
  let response = { response with Packet.answers = answers } in
  if result = ConflictRestart then
    (* If we lose a simultaneous probe tie-break then we have to delay 1 second *)
    (* TODO: if there are more than 15 conflicts in 10 seconds then we are
       supposed to wait 5 seconds *)
    (response,
     restart_later {
       state with
       (* Reset probing names back to pending *)
       names_pending = UniqueSet.union state.names_pending state.names_probing;
       names_probing = UniqueSet.empty;
     } 1.0,
     ConflictRestart)
  else
    (response, state, NoConflict)

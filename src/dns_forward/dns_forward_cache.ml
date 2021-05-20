(*
 * Copyright (C) 2016 David Scott <dave@recoil.org>
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
 *)

module Question = struct
  module M = struct
    type t = Dns.Packet.question

    (* Stdlib.compare is ok because the question consists of a record of
       constant constructors and a string list. Ideally ocaml-dns would provide
       nice `compare` functions. *)
    let compare = Stdlib.compare
  end
  module Map = Map.Make(M)
  include M
end

module Address = Dns_forward_config.Address

type answer = {
  rrs: Dns.Packet.rr list;
  (* We'll use the Lwt scheduler as a priority queue to expire records, one
     timeout thread per record. *)
  timeout: unit Lwt.t;
}

module Make(Time: Mirage_time_lwt.S) = struct
  type t = {
    max_bindings: int;
    (* For every question we store a mapping of server address to the answer *)
    mutable cache: answer Address.Map.t Question.Map.t;
  }

  let make ?(max_bindings=1024) () =
    let cache = Question.Map.empty in
    { max_bindings; cache }

  let answer t address question =
    if Question.Map.mem question t.cache then begin
      let all = Question.Map.find question t.cache in
      if Address.Map.mem address all
      then Some (Address.Map.find address all).rrs
      else None
    end else None

  let remove t question =
    if Question.Map.mem question t.cache then begin
      let all = Question.Map.find question t.cache in
      Address.Map.iter (fun _ answer -> Lwt.cancel answer.timeout) all;
      t.cache <- Question.Map.remove question t.cache;
    end

  let destroy t =
    Question.Map.iter (fun _ all ->
        Address.Map.iter (fun _ answer ->
            Lwt.cancel answer.timeout) all) t.cache;
    t.cache <- Question.Map.empty

  let insert t address question rrs =
    (* If we already have the maximum number of bindings then remove one at
       random *)
    if Question.Map.cardinal t.cache >= t.max_bindings then begin
      let choice = Random.int (Question.Map.cardinal t.cache) in
      match Question.Map.fold (fun question _ (i, existing) ->
          i + 1, if i = choice then Some question else existing
        ) t.cache (0, None) with
      | _, None -> (* should never happen *) ()
      | _, Some question -> remove t question
    end;
    (* Each resource record could be expired separately using a different TTL
       but we'll simplify the code by expiring all resource records received
       from the same server address when the lowest TTL is exceeded. *)
    let min_ttl =
      List.fold_left min Int32.max_int
        (List.map (fun rr -> rr.Dns.Packet.ttl) rrs)
    in
    let timeout =
      let open Lwt.Infix in
      Time.sleep_ns (Duration.of_sec @@ Int32.to_int min_ttl)
      >>= fun () ->
      if Question.Map.mem question t.cache then begin
        let address_to_answer =
          Question.Map.find question t.cache
          |> Address.Map.remove address in
        if Address.Map.is_empty address_to_answer
        then t.cache <- Question.Map.remove question t.cache
        else t.cache <- Question.Map.add question address_to_answer t.cache
      end;
      Lwt.return_unit
    in
    let answer = { rrs; timeout } in
    let address_to_answer =
      if Question.Map.mem question t.cache
      then Question.Map.find question t.cache
      else Address.Map.empty
    in
    t.cache <- Question.Map.add question
        (Address.Map.add address answer address_to_answer) t.cache
end

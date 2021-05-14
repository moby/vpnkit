(*
 * Copyright (c) 2012 Richard Mortier <mort@cantab.net>
 * Copyright (c) 2013-2015 David Sheets <sheets@alum.mit.edu>
 * Copyright (c) 2014 Anil Madhavapeddy <anil@recoil.org>
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
open Dns
open Operators
open Protocol

module DP = Packet

type result = Answer of DP.t | Error of exn

type commfn = {
  txfn    : Cstruct.t -> unit Lwt.t;
  rxfn    : (Cstruct.t -> Dns.Packet.t option) -> DP.t Lwt.t;
  timerfn : unit -> unit Lwt.t;
  cleanfn : unit -> unit Lwt.t;
}

let rec send_req txfn timerfn q =
  function
  | 0 -> Lwt.return_unit
  | count ->
    txfn q >>= fun () ->
    timerfn () >>= fun () ->
    send_req txfn timerfn q (count - 1)

let send_pkt client ?alloc ({ txfn; rxfn; timerfn; _ }) pkt =
  let module R = (val client : CLIENT) in
  let cqpl = R.marshal ?alloc pkt in
  let resl = List.map (fun (ctxt,q) ->
    (* make a new socket for each request flavor *)
    (* start the requests in parallel and run them until success or timeout*)
    let t, w = Lwt.wait () in
    Lwt.async (fun () -> Lwt.pick [
      (send_req txfn timerfn q 4 >|= fun () -> Error (R.timeout ctxt));
      (Lwt.catch
         (fun () -> rxfn (R.parse ctxt) >|= fun r -> Answer r)
         (fun exn -> Lwt.return (Error exn))
      )
    ] >|= Lwt.wakeup w);
    t
  ) cqpl in
  (* return an answer or all the errors if no request succeeded *)
  let rec select errors = function
    | [] -> Lwt.fail (Dns_resolve_error errors)
    | ts ->
      Lwt.nchoose_split ts
      >>= fun (rs, ts) ->
      let rec find_answer errors = function
        | [] -> select errors ts
        | (Answer a)::_ -> Lwt.return a
        | (Error e)::r -> find_answer (e::errors) r
      in
      find_answer errors rs
  in select [] resl

let resolve_pkt client ?alloc (commfn:commfn) pkt =
  Lwt.catch (fun () ->
      send_pkt client ?alloc commfn pkt
      >>= fun r -> commfn.cleanfn ()
      >>= fun () -> Lwt.return r)
    (function exn ->
      commfn.cleanfn () >>= fun () ->
      Lwt.fail exn)

let resolve client
    ?alloc
    ?(dnssec=false)
    (commfn:commfn)
    (q_class:DP.q_class) (q_type:DP.q_type)
    (q_name:Name.t) =
  let id = (let module R = (val client : CLIENT) in R.get_id ()) in
  let q = Dns.Query.create ~id ~dnssec q_class q_type q_name in
  resolve_pkt client ?alloc commfn q

let gethostbyname
    ?alloc
    ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_A)
    commfn
    name =
  let open DP in
  let domain = Name.of_string name in
  resolve (module Dns.Protocol.Client) ?alloc commfn q_class q_type domain
  >|= fun r ->
  List.fold_left (fun a x ->
      match x.rdata with
      | A ip -> Ipaddr.V4 ip :: a
      | AAAA ip -> Ipaddr.V6 ip :: a
      | _ -> a
    ) [] r.answers
  |> List.rev

let gethostbyaddr
    ?alloc
    ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_PTR)
    commfn
    addr
  =
  let addr = Name.of_ipaddr (Ipaddr.V4 addr) in
  let open DP in
  resolve (module Dns.Protocol.Client) ?alloc commfn q_class q_type addr
  >|= fun r ->
  List.fold_left (fun a x ->
      match x.rdata with |PTR n -> (Name.to_string n)::a |_->a
    ) [] r.answers
  |> List.rev

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
open Dns_forward
module Error = Error.Infix

let bad_question = Dns.Packet.make_question Dns.Packet.Q_A (Dns.Name.of_string "this.is.a.bad.question.")

module Make(Server: Rpc.Server.S) = struct
  type t = {
    names: (string * Ipaddr.t) list;
    mutable nr_queries: int;
    delay: float;
    mutable simulate_bad_question: bool;
  }
  let make ?(delay=0.) ?(simulate_bad_question = false) names =
    { names; nr_queries = 0; delay; simulate_bad_question }

  let get_nr_queries { nr_queries; _ } = nr_queries

  let answer buffer t =
    t.nr_queries <- t.nr_queries + 1;
    let open Lwt.Infix in
    Lwt_unix.sleep t.delay
    >>= fun () ->
    let len = Cstruct.length buffer in
    let buf = buffer in
    match Dns.Protocol.Server.parse (Cstruct.sub buf 0 len) with
    | Some request ->
        let open Dns.Packet in
        begin match request with
        | { id; detail; additionals; questions = [ { q_class = Q_IN; q_type = Q_A; q_name; _ } ]; _ } ->
            begin match List.fold_left (fun found (name, ip) -> match found, ip with
              | Some v4, _           -> Some v4
              | None,   Ipaddr.V4 v4 ->
                  if Dns.Name.to_string q_name = name then Some v4 else None
              | None,   Ipaddr.V6 _  -> None
              ) None t.names with
            | None ->
                let answers = [] in
                let detail = { detail with
                               Dns.Packet.qr = Dns.Packet.Response;
                               rcode = Dns.Packet.NXDomain
                             } in
                let questions = match t.simulate_bad_question with
                | true -> [ bad_question ]
                | false -> request.questions in
                let pkt = { Dns.Packet.id; detail; questions; authorities=[]; additionals; answers } in
                let buf = Dns.Packet.marshal pkt in
                Lwt.return (Ok buf)
            | Some v4 ->
                let answers = [ { name = q_name; cls = RR_IN; flush = false; ttl = 0l; rdata = A v4 } ] in
                let detail = { detail with Dns.Packet.qr = Dns.Packet.Response } in
                let questions = match t.simulate_bad_question with
                | true -> [ bad_question ]
                | false -> request.questions in
                let pkt = { Dns.Packet.id; detail; questions; authorities=[]; additionals; answers } in
                let buf = Dns.Packet.marshal pkt in
                Lwt.return (Ok buf)
            end
        | _ ->
            Lwt.return (Error (`Msg "unexpected query type"))
        end
    | None ->
        Lwt.return (Error (`Msg "failed to parse request"))

  type server = Server.server

  let serve ~address t =
    let open Error in
    Server.bind address
    >>= fun server ->
    Server.listen server (fun buf -> answer buf t)
    >>= fun () ->
    Lwt.return (Ok server)

  let shutdown = Server.shutdown

end

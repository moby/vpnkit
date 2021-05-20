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

let src =
  let src = Logs.Src.create "Dns_forward" ~doc:"DNS serving" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

open Lwt.Infix

module type S = Dns_forward_s.SERVER

module Make(Server: Dns_forward_s.RPC_SERVER)(Resolver: Dns_forward_s.RESOLVER) = struct

  type resolver = Resolver.t

  type t = {
    resolver: Resolver.t;
    mutable server: Server.server option;
  }

  let create resolver =
    Lwt.return { resolver; server = None }

  let serve ~address t =
    let open Lwt_result.Infix in
    Server.bind address
    >>= fun server ->
    t.server <- Some server;
    Server.listen server (fun buf -> Resolver.answer buf t.resolver)
    >>= fun () ->
    Lwt_result.return ()

  let destroy { resolver; server } =
    Resolver.destroy resolver
    >>= fun () ->
    match server with
    | None -> Lwt.return_unit
    | Some server -> Server.shutdown server
end

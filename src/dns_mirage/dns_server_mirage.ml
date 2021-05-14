(*
 * Copyright (c) 2015 Heidi Howard <hh360@cam.ac.uk>
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

open Lwt
open Dns_server
open Result

module type S = sig
  type t
  type stack
  type kv_ro

  val create : stack -> kv_ro -> t
  val eventual_process_of_zonefiles : t -> string list -> Dns.Packet.t process Lwt.t
  val serve_with_processor: t -> port:int -> processor:(module PROCESSOR) -> unit Lwt.t
  val serve_with_zonefile : t -> port:int -> zonefile:string -> unit Lwt.t
  val serve_with_zonefiles : t -> port:int -> zonefiles:string list -> unit Lwt.t
  val serve_with_zonebuf : t -> port:int -> zonebuf:string -> unit Lwt.t
  val serve_with_zonebufs : t-> port:int -> zonebufs:string list -> unit Lwt.t
end

module Make(K:Mirage_kv_lwt.RO)(S:Mirage_stack_lwt.V4) = struct

  type stack = S.t
  type kv_ro = K.t
  type t = {s: S.t; k: K.t}

  let create s k = {s;k}

  let fail_load message = fail (Failure ("Dns_server_mirage: "^message))

  let eventual_process_of_zonefiles t filenames =
    Lwt_list.map_s (fun filename ->
      K.size t.k filename
      >>= function
      | Error _ -> fail_load ("zonefile "^filename^" not found")
      | Ok sz ->
        K.read t.k filename 0L sz
        >>= function
        | Error _  -> fail_load ("error reading zonefile "^filename)
        | Ok pages -> return (Cstruct.copyv pages)
    ) filenames
    >|= process_of_zonebufs

  let serve_with_processor t ~port ~processor =
    let udp = S.udpv4 t.s in
    let listener ~src ~dst ~src_port buf =
      let src' = (Ipaddr.V4 dst), port in
      let dst' = (Ipaddr.V4 src), src_port in
      process_query buf (Cstruct.len buf) src' dst' processor
      >>= function
      | None -> return ()
      | Some rba ->
        (* Do not attempt to retry if serving failed *)
        S.UDPV4.write ~src_port:port ~dst:src ~dst_port:src_port udp rba >|= fun _ -> ()
    in
    S.listen_udpv4 t.s ~port listener;
    S.listen t.s

  let serve_with_zonebufs t ~port ~zonebufs =
    let process = process_of_zonebufs zonebufs in
    let processor = (processor_of_process process :> (module PROCESSOR)) in
    serve_with_processor t ~port ~processor

  let serve_with_zonebuf t ~port ~zonebuf =
    serve_with_zonebufs t ~port ~zonebufs:[zonebuf]

  let serve_with_zonefiles t ~port ~zonefiles =
    eventual_process_of_zonefiles t zonefiles
    >>= fun process ->
    let processor = (processor_of_process process :> (module PROCESSOR)) in
    serve_with_processor t ~port ~processor

  let serve_with_zonefile t ~port ~zonefile =
    serve_with_zonefiles t ~port ~zonefiles:[zonefile]

end

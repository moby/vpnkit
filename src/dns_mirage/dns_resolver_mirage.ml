(*
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

open Lwt
open Dns
open Dns_resolver
open Result

module DP = Packet

let default_ns = Ipaddr.V4.of_string_exn "8.8.8.8"
let default_port = 53

module type S = sig
  type t
  type stack

  val create : stack -> t

  val resolve :
    (module Protocol.CLIENT) ->
    t -> Ipaddr.V4.t -> int ->
    Packet.q_class ->
    Packet.q_type ->
    Name.t ->
    Packet.t Lwt.t

  val gethostbyname : t ->
    ?server:Ipaddr.V4.t -> ?dns_port:int ->
    ?q_class:Dns.Packet.q_class ->
    ?q_type:Dns.Packet.q_type ->
    string -> Ipaddr.t list Lwt.t

  val gethostbyaddr : t ->
    ?server:Ipaddr.V4.t -> ?dns_port:int ->
    ?q_class:Dns.Packet.q_class ->
    ?q_type:Dns.Packet.q_type ->
    Ipaddr.V4.t -> string list Lwt.t
end

type static_dns = {
  names: (string, Ipaddr.t) Hashtbl.t;
  rev: (Ipaddr.V4.t, string) Hashtbl.t;
}

module Static = struct
  type stack = static_dns
  type t = stack

  let create s = s

  let resolve _client
      _s _server _dns_port
      (_q_class:DP.q_class) (_q_type:DP.q_type)
      (_q_name:Name.t) =
    fail (Failure "Dummy stack cannot call resolve")

  let gethostbyname
      s ?server:_ ?dns_port:_
      ?q_class:_ ?q_type:_
      name =
    return (Hashtbl.find_all s.names name)

  let gethostbyaddr
      s ?server:_ ?dns_port:_
      ?q_class:_ ?q_type:_
      addr =
   return (Hashtbl.find_all s.rev addr)
end

module Make(Time:Mirage_time.S)(S:Mirage_stack.V4) = struct

  type stack = S.t
  type endp = Ipaddr.V4.t * int

  type t = {
    s: S.t;
    res: (endp, Dns_resolver.commfn) Hashtbl.t;
  }

  let create s =
    let res = Hashtbl.create 3 in
    { s; res }

  let connect_to_resolver {s; res} ((dst,dst_port) as endp) =
    let udp = S.udpv4 s in
    try
      Hashtbl.find res endp
    with Not_found ->
      let timerfn () = Time.sleep_ns (Duration.of_sec 5) in
      let mvar = Lwt_mvar.create_empty () in
      (* TODO: test that port is free. Needs more functions exposed in tcpip *)
      let src_port = (Random.int 64511) + 1024 in
      let callback ~src:_ ~dst:_ ~src_port:_ buf = Lwt_mvar.put mvar buf in
      let cleanfn () = return () in
      S.listen_udpv4 s ~port:src_port callback;
      let txfn buf =
        S.UDPV4.write ~src_port ~dst ~dst_port udp buf >>= function
        | Error e ->
          Fmt.kstrf fail_with
            "Attempting to communicate with remote resolver: %a"
            S.UDPV4.pp_error e
        | Ok () -> Lwt.return_unit
      in
      let rec rxfn f =
        Lwt_mvar.take mvar
        >>= fun buf ->
        match f buf with
        | None -> rxfn f
        | Some packet -> return packet
      in
      let commfn = { txfn; rxfn; timerfn; cleanfn } in
      Hashtbl.add res endp commfn;
      commfn

  let resolve client
      s server dns_port
      (q_class:DP.q_class) (q_type:DP.q_type)
      (q_name:Name.t) =
    let commfn = connect_to_resolver s (server,dns_port) in
    resolve client commfn q_class q_type q_name

  let gethostbyname
      s ?(server = default_ns) ?(dns_port = default_port)
      ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_A)
      name =
    let commfn = connect_to_resolver s (server,dns_port) in
    gethostbyname ~q_class ~q_type commfn name

  let gethostbyaddr
      s ?(server = default_ns) ?(dns_port = default_port)
      ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_PTR)
      addr =
    let commfn = connect_to_resolver s (server,dns_port) in
    gethostbyaddr ~q_class ~q_type commfn addr

end

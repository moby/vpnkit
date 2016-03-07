(*
 * Copyright (C) 2016 David Scott <dave.scott@docker.com>
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

type configuration = {
  local_ip: Ipaddr.V4.t;
  peer_ip: Ipaddr.V4.t;
  low_ip: Ipaddr.V4.t; (* FIXME: this is needed by the DHCP server for no good reason *)
  high_ip: Ipaddr.V4.t; (* FIXME: this is needed by the DHCP server for no good reason *)
  prefix: Ipaddr.V4.Prefix.t;
  mac: Macaddr.t;
}

(* Compute the smallest IPv4 network which includes both [a_ip]
   and all [other_ips]. *)
let rec smallest_prefix a_ip other_ips = function
  | 0 -> Ipaddr.V4.Prefix.global
  | bits ->
    let prefix = Ipaddr.V4.Prefix.make bits a_ip in
    if List.for_all (fun b_ip -> Ipaddr.V4.Prefix.mem b_ip prefix) other_ips
    then prefix
    else smallest_prefix a_ip other_ips (bits - 1)

let make ~peer_ip ~local_ip =
  let mac = Macaddr.of_string_exn "0F:F1:CE:0F:F1:CE" in
  (* FIXME: We need a third IP just to make the DHCP server happy *)
  let low_ip, high_ip =
    let open Ipaddr.V4 in
    let highest = if compare local_ip peer_ip < 0 then peer_ip else local_ip in
    let i32 = to_int32 highest in
    of_int32 @@ Int32.succ i32, of_int32 @@ Int32.succ @@ Int32.succ i32 in
  let prefix = smallest_prefix peer_ip [ local_ip; low_ip; high_ip ] 32 in
  { local_ip; peer_ip; low_ip; high_ip; prefix; mac }

let dhcp_conf ~config =
  let network = Ipaddr.V4.(to_string (Prefix.network config.prefix)) in
  let netmask = Ipaddr.V4.(to_string (Prefix.netmask config.prefix)) in
  let local_ip = Ipaddr.V4.to_string config.local_ip in
  let peer_ip = Ipaddr.V4.to_string config.peer_ip in
  let low_ip = Ipaddr.V4.to_string config.low_ip in
  let high_ip = Ipaddr.V4.to_string config.high_ip in

  Printf.sprintf "
  option domain-name \"local\";
  subnet %s netmask %s {
    option routers %s;
    option domain-name-servers %s;
    range %s %s;
    host xhyve {
      hardware ethernet c0:ff:ee:c0:ff:ee;
      fixed-address %s;
    }
  }
  " network netmask local_ip local_ip low_ip high_ip peer_ip

let src =
  let src = Logs.Src.create "tcpip" ~doc:"Mirage TCP/IP" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Netif = Filter.Make(Vmnet)

module Ethif1 = Ethif.Make(Netif)

module Arpv41 = Arp.Make(Ethif1)

module Ipv41 = Ipv4.Make(Ethif1)(Arpv41)

module Udp1 = Udp.Make(Ipv41)

module Tcp1 = Tcp.Flow.Make(Ipv41)(OS.Time)(Clock)(Random)

include Tcpip_stack_direct.Make(Console_unix)(OS.Time)
    (Random)(Netif)(Ethif1)(Arpv41)(Ipv41)(Udp1)(Tcp1)

module Dhcp = struct
  let of_interest mac dest =
    Macaddr.compare dest mac = 0 || not (Macaddr.is_unicast dest)

  let input net config subnet buf =
    let open Lwt.Infix in
    let open Dhcp_server.Input in
    match (Dhcp_wire.pkt_of_buf buf (Cstruct.len buf)) with
    | `Error e ->
      Log.err (fun f -> f "failed to parse DHCP packet: %s" e);
      Lwt.return ()
    | `Ok pkt ->
      match (input_pkt config subnet pkt (Clock.time ())) with
      | Silence -> Lwt.return_unit
      | Warning w ->
        Log.warn (fun f -> f "%s" w);
        Lwt.return ()
      | Error e ->
        Log.err (fun f -> f "%s" e);
        Lwt.return ()
      | Reply reply ->
        let open Dhcp_wire in
        Log.info (fun f -> f "%s from %s" (op_to_string pkt.op) (Macaddr.to_string (pkt.srcmac)));
        Netif.write net (Dhcp_wire.buf_of_pkt reply)
        >>= fun () ->
        let domain = List.fold_left (fun acc x -> match x with
          | Domain_name y -> y
          | _ -> acc) "unknown" reply.options in
        let dns = List.fold_left (fun acc x -> match x with
          | Dns_servers ys -> String.concat ", " (List.map Ipaddr.V4.to_string ys)
          | _ -> acc) "none" reply.options in
        let routers = List.fold_left (fun acc x -> match x with
          | Routers ys -> String.concat ", " (List.map Ipaddr.V4.to_string ys)
          | _ -> acc) "none" reply.options in
        Log.info (fun f -> f "%s to %s yiddr %s siddr %s dns %s router %s domain %s"
          (op_to_string reply.op) (Macaddr.to_string (reply.dstmac))
          (Ipaddr.V4.to_string reply.yiaddr) (Ipaddr.V4.to_string reply.siaddr)
          dns routers domain
        );
        Lwt.return ()

  let config ~config =
    Dhcp_server.Config.parse (dhcp_conf ~config) [(config.local_ip, config.mac)]

  let listen mac config net buf =
    let subnet = List.hd config.Dhcp_server.Config.subnets in
    match (Wire_structs.parse_ethernet_frame buf) with
    | Some (proto, dst, payload) when of_interest mac dst ->
      (match proto with
       | Some Wire_structs.IPv4 ->
         if Dhcp_wire.is_dhcp buf (Cstruct.len buf) then
           input net config subnet buf
         else
           Lwt.return_unit
       | _ -> Lwt.return_unit)
    | _ -> Lwt.return_unit
end

module Infix = struct
  open Lwt.Infix
  let ( >>= ) m f = m >>= function
    | `Ok x -> f x
    | `Error x -> Lwt.return (`Error x)
end

let or_error name m =
  let open Lwt.Infix in
  m >>= function
  | `Error _ -> Lwt.return (`Error (`Msg (Printf.sprintf "Failed to connect %s device" name)))
  | `Ok x -> Lwt.return (`Ok x)

let connect ~config (ppp: Vmnet.t) =
  let open Infix in
  let valid_sources = [ config.peer_ip; Ipaddr.V4.of_string_exn "0.0.0.0" ] in
  let arp_table = [
    config.peer_ip, Vmnet.mac ppp;
    config.local_ip, config.mac;
  ] in
  or_error "filter" @@ Netif.connect ~valid_sources ppp
  >>= fun interface ->
  or_error "console" @@ Console_unix.connect "0"
  >>= fun console ->
  or_error "ethernet" @@ Ethif1.connect interface
  >>= fun ethif ->
  or_error "arp" @@ Arpv41.connect ~table:arp_table ethif
  >>= fun arp ->
  or_error "ipv4" @@ Ipv41.connect ethif arp
  >>= fun ipv4 ->
  or_error "udp" @@ Udp1.connect ipv4
  >>= fun udp4 ->
  or_error "tcp" @@ Tcp1.connect ipv4
  >>= fun tcp4 ->
  let netmask = Ipaddr.V4.Prefix.netmask config.prefix in
  let cfg = {
    V1_LWT. name = "stackv4_ip";
    console;
    interface;
    mode = `IPv4 (config.local_ip, netmask, []);
  } in
  or_error "stack" @@ connect cfg ethif arp ipv4 udp4 tcp4
  >>= fun stack ->
  (* Hook in the DHCP server too *)
  let open Lwt.Infix in
  let dhcp_config = Dhcp.config ~config in
  Netif.add_listener interface (Dhcp.listen config.mac dhcp_config interface);
  Lwt.return (`Ok stack)

(* FIXME: this is unnecessary, mirage-flow should be changed *)
module TCPV4_half_close = struct
  include TCPV4
  let shutdown_read flow =
    (* No change to the TCP PCB: all this means is that I've
       got my finders in my ears and am nolonger listening to
       what you say. *)
    Lwt.return ()
  let shutdown_write = close
end

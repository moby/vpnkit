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

let ip = Ipaddr.V4.of_string_exn "10.0.0.1"
let peer_ip = Ipaddr.V4.of_string_exn "10.0.0.2"
let mac = Macaddr.of_string_exn "0F:F1:CE:0F:F1:CE"
let netmask = Ipaddr.V4.of_string_exn "255.255.255.0"

let dhcp_conf = Printf.sprintf "
  option  domain-name \"docker.com\";
  subnet 10.0.0.0 netmask 255.255.255.0 {
    option routers %s;
    option domain-name-servers %s;
    range 10.0.0.100 10.0.0.200;
    host xhyve {
      hardware ethernet c0:ff:ee:c0:ff:ee;
      fixed-address %s;
    }
  }
" (Ipaddr.V4.to_string ip) (Ipaddr.V4.to_string ip) (Ipaddr.V4.to_string peer_ip)

module Source_ips = struct
  let valid_sources = [ peer_ip; Ipaddr.V4.of_string_exn "0.0.0.0" ]
end

let src =
	let src = Logs.Src.create "tcpip" ~doc:"Mirage TCP/IP" in
	Logs.Src.set_level src (Some Logs.Info);
	src

module Log = (val Logs.src_log src : Logs.LOG)

module Netif = Filter.Only_source_ipv4(Source_ips)(Ppp)

module Ethif1 = Ethif.Make(Netif)

module Arpv41 = Arpv4.Make(Ethif1)(Clock)(OS.Time)

module Ipv41 = Ipv4.Make(Ethif1)(Arpv41)

module Udp1 = Udp.Make(Ipv41)

module Tcp1 = Tcp.Flow.Make(Ipv41)(OS.Time)(Clock)(Random)

include Tcpip_stack_direct.Make(Console_unix)(OS.Time)
  (Random)(Netif)(Ethif1)(Arpv41)(Ipv41)(Udp1)(Tcp1)

module Dhcp = struct
  let of_interest dest =
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
        Log.info (fun f -> f "Received packet %s" (Dhcp_wire.pkt_to_string pkt));
        Netif.write net (Dhcp_wire.buf_of_pkt reply)
        >>= fun () ->
        Log.info (fun f -> f "Sent reply %s" (Dhcp_wire.pkt_to_string reply));
        Lwt.return ()

  let config = Dhcp_server.Config.parse dhcp_conf [(ip, mac)]
  let subnet = List.hd config.Dhcp_server.Config.subnets

  let listen net buf =
    match (Wire_structs.parse_ethernet_frame buf) with
    | Some (proto, dst, payload) when of_interest dst ->
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

let connect (ppp: Ppp.t) =
  let open Infix in
  or_error "filter" @@ Netif.connect ppp
  >>= fun interface ->
  or_error "console" @@ Console_unix.connect "0"
  >>= fun console ->
  or_error "ethernet" @@ Ethif1.connect interface
  >>= fun ethif ->
  or_error "arp" @@ Arpv41.connect ethif
  >>= fun arp ->
  or_error "ipv4" @@ Ipv41.connect ethif arp
  >>= fun ipv4 ->
  or_error "udp" @@ Udp1.connect ipv4
  >>= fun udp4 ->
  or_error "tcp" @@ Tcp1.connect ipv4
  >>= fun tcp4 ->
  let config = {
    V1_LWT. name = "stackv4_ip";
    console;
    interface;
    mode = `IPv4 (ip, netmask, []);
  } in
  or_error "stack" @@ connect config ethif arp ipv4 udp4 tcp4
  >>= fun stack ->
  (* Hook in the DHCP server too *)
  let open Lwt.Infix in
  Netif.add_listener interface (Dhcp.listen interface);
  Lwt.return (`Ok stack)

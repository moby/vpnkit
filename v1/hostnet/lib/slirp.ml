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
open Lwt

let src =
  let src = Logs.Src.create "usernet" ~doc:"Mirage TCP/IP <-> socket proxy" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let client_macaddr = Macaddr.of_string_exn "C0:FF:EE:C0:FF:EE"
(* random MAC from https://www.hellion.org.uk/cgi-bin/randmac.pl *)
let server_macaddr = Macaddr.of_string_exn "F6:16:36:BC:F9:C6"

let mtu = 1452 (* packets above this size with DNF set will get ICMP errors *)

let finally f g =
  Lwt.catch (fun () -> f () >>= fun r -> g () >>= fun () -> return r) (fun e -> g () >>= fun () -> fail e)

let log_exception_continue description f =
  Lwt.catch
    (fun () -> f ())
    (fun e ->
       Log.err (fun f -> f "%s: caught %s" description (Printexc.to_string e));
       Lwt.return ()
    )

let restart_on_change name to_string values =
  Active_config.tl values
  >>= fun values ->
  let v = Active_config.hd values in
  Log.info (fun f -> f "%s changed to %s in the database: restarting" name (to_string v));
  exit 1

type pcap = (string * int64 option) option

let print_pcap = function
  | None -> "disabled"
  | Some (file, None) -> "capturing to " ^ file ^ " with no limit"
  | Some (file, Some limit) -> "capturing to " ^ file ^ " but limited to " ^ (Int64.to_string limit)

module Make(Vmnet: Sig.VMNET)(Resolv_conv: Sig.RESOLV_CONF) = struct
  module Tcpip_stack = Tcpip_stack.Make(Vmnet)
  module Dns_forward = Dns_forward.Make(Tcpip_stack)(Resolv_conv)

let connect x peer_ip local_ip =
  let config = Tcpip_stack.make ~client_macaddr ~server_macaddr ~peer_ip ~local_ip in
        begin Tcpip_stack.connect ~config x
        >>= function
        | `Error (`Msg m) -> failwith m
        | `Ok s ->
            Tcpip_stack.listen_udpv4 s 53 (Dns_forward.input s);
            Vmnet.add_listener x (
              fun buf ->
                match (Wire_structs.parse_ethernet_frame buf) with
                | Some (Some Wire_structs.IPv4, _, payload) ->
                  let src = Ipaddr.V4.of_int32 @@ Wire_structs.Ipv4_wire.get_ipv4_src payload in
                  let dst = Ipaddr.V4.of_int32 @@ Wire_structs.Ipv4_wire.get_ipv4_dst payload in
                  begin match Wire_structs.Ipv4_wire.(int_to_protocol @@ get_ipv4_proto payload) with
                    | Some `UDP ->
                      let hlen_version = Wire_structs.Ipv4_wire.get_ipv4_hlen_version payload in
                      let ihl = hlen_version land 0xf in
                      let udp = Cstruct.shift payload (ihl * 4) in
                      let src_port = Wire_structs.get_udp_source_port udp in
                      let dst_port = Wire_structs.get_udp_dest_port udp in
                      let length = Wire_structs.get_udp_length udp in
                      let flags_fragment_offset = Wire_structs.Ipv4_wire.get_ipv4_off payload in
                      let dnf = ((flags_fragment_offset lsr 8) land 0x40) <> 0 in
                      if Cstruct.len udp < length then begin
                        Log.err (fun f -> f "Dropping UDP %s:%d -> %s:%d reported len %d actual len %d"
                                     (Ipaddr.V4.to_string src) src_port
                                     (Ipaddr.V4.to_string dst) dst_port
                                     length (Cstruct.len udp));
                        Lwt.return_unit
                      end else if dnf && (Cstruct.len payload > mtu) then begin
                        let would_fragment ~ip_header ~ip_payload =
                          let open Wire_structs.Ipv4_wire in
                          let header = Cstruct.create sizeof_icmpv4 in
                          set_icmpv4_ty header 0x03;
                          set_icmpv4_code header 0x04;
                          set_icmpv4_csum header 0x0000;
                          (* this field is unused for icmp destination unreachable *)
                          set_icmpv4_id header 0x00;
                          set_icmpv4_seq header mtu;
                          let icmp_payload = match ip_payload with
                            | Some ip_payload ->
                              if (Cstruct.len ip_payload > 8) then begin
                                let ip_payload = Cstruct.sub ip_payload 0 8 in
                                Cstruct.append ip_header ip_payload
                              end else Cstruct.append ip_header ip_payload
                            | None -> ip_header
                          in
                          set_icmpv4_csum header
                            (Tcpip_checksum.ones_complement_list [ header;
                                                                   icmp_payload ]);
                          let icmp_packet = Cstruct.append header icmp_payload in
                          icmp_packet
                        in
                        let ethernet_frame, len = Tcpip_stack.IPV4.allocate (Tcpip_stack.ipv4 s)
                          ~src:dst ~dst:src ~proto:`ICMP in
                        let ethernet_ip_hdr = Cstruct.sub ethernet_frame 0 len in

                        let reply = would_fragment
                            ~ip_header:(Cstruct.sub payload 0 (ihl * 4))
                            ~ip_payload:(Some (Cstruct.sub payload (ihl * 4) 8)) in
                        (* Rather than silently unset the do not fragment bit, we
                           respond with an ICMP error message which will
                           hopefully prompt the other side to send messages we
                           can forward *)
                        Log.err (fun f -> f
                                    "Sending icmp-dst-unreachable in response to UDP %s:%d -> %s:%d with DNF set IPv4 len %d"
                                     (Ipaddr.V4.to_string src) src_port
                                     (Ipaddr.V4.to_string dst) dst_port
                                     length);
                        Tcpip_stack.IPV4.writev (Tcpip_stack.ipv4 s) ethernet_ip_hdr [ reply ];
                      end else begin
                        let payload = Cstruct.sub udp Wire_structs.sizeof_udp (length - Wire_structs.sizeof_udp) in
                        (* We handle DNS on port 53 ourselves, see [listen_udpv4] above *)
                        (* ... but if it's going to an external IP then we treat it like all other
                           UDP and NAT it *)
                        if Ipaddr.V4.compare dst local_ip != 0 then begin
                          Log.debug (fun f -> f "UDP %s:%d -> %s:%d len %d"
                                       (Ipaddr.V4.to_string src) src_port
                                       (Ipaddr.V4.to_string dst) dst_port
                                       length
                                   );
                          let reply buf = Tcpip_stack.UDPV4.writev ~source_ip:dst ~source_port:dst_port ~dest_ip:src ~dest_port:src_port (Tcpip_stack.udpv4 s) [ buf ] in
                          Socket.Datagram.input ~reply ~src:(src, src_port) ~dst:(dst, dst_port) ~payload
                        end else Lwt.return_unit
                      end
                    | _ -> Lwt.return_unit
                  end
                | _ -> Lwt.return_unit
            );
            Tcpip_stack.listen_tcpv4_flow s (
              fun ~src:(src_ip, src_port) ~dst:(dst_ip, dst_port) ->
                let description =
                  Printf.sprintf "TCP %s:%d > %s:%d"
                    (Ipaddr.V4.to_string src_ip) src_port
                    (Ipaddr.V4.to_string dst_ip) dst_port in
                Log.debug (fun f -> f "%s connecting" description);
                ( if Ipaddr.V4.compare src_ip local_ip == 0 && src_port = 53 then begin
                    Dns_resolver_unix.create () (* re-read /etc/resolv.conf *)
                    >>= function
                    | { Dns_resolver_unix.servers = (Ipaddr.V4 ip, port) :: _ } -> Lwt.return (ip, port)
                    | _ ->
                      Log.err (fun f -> f "Failed to discover DNS server: assuming 127.0.01");
                      Lwt.return (Ipaddr.V4.of_string_exn "127.0.0.1", 53)
                  end else Lwt.return (src_ip, src_port)
                ) >>= fun (src_ip, src_port) ->
                Socket.Stream.connect_v4 src_ip src_port
                >>= function
                | `Error (`Msg m) ->
                  Log.info (fun f -> f "%s rejected: %s" description m);
                  return `Reject
                | `Ok remote ->
                  Lwt.return (`Accept (fun local ->
                      finally (fun () ->
                          (* proxy between local and remote *)
                          Log.debug (fun f -> f "%s connected" description);
                          Mirage_flow.proxy (module Clock) (module Tcpip_stack.TCPV4_half_close) local (module Socket.Stream) remote ()
                          >>= function
                          | `Error (`Msg m) ->
                            Log.err (fun f -> f "%s proxy failed with %s" description m);
                            return ()
                          | `Ok (l_stats, r_stats) ->
                            Log.debug (fun f ->
                                f "%s closing: l2r = %s; r2l = %s" description
                                  (Mirage_flow.CopyStats.to_string l_stats) (Mirage_flow.CopyStats.to_string r_stats)
                              );
                            return ()
                        ) (fun () ->
                          Socket.Stream.close remote
                          >>= fun () ->
                          Log.debug (fun f -> f "%s Socket.Stream.close" description);
                          Lwt.return ()
                        )
                    ))
            );
            Tcpip_stack.listen s
            >>= fun () ->
            Log.info (fun f -> f "TCP/IP ready");
            Lwt.return ()
        end

  type t = {
    peer_ip: Ipaddr.V4.t;
    local_ip: Ipaddr.V4.t;
    pcap_settings: pcap Active_config.values;
  }

  let create config =
    let driver = [ "com.docker.driver.amd64-linux" ] in

    let pcap_path = driver @ [ "slirp"; "capture" ] in
    Active_config.string_option config pcap_path
    >>= fun string_pcap_settings ->
    let parse_pcap = function
      | None -> Lwt.return None
      | Some x ->
        begin match Stringext.split (String.trim x) ~on:':' with
        | [ filename ] ->
          (** Assume 10MiB limit for safety *)
          Lwt.return (Some (filename, Some 16777216L))
        | [ filename; limit ] ->
          let limit =
            try
              Int64.of_string limit
            with
            | _ -> 16777216L in
          let limit = if limit = 0L then None else Some limit in
          Lwt.return (Some (filename, limit))
        | _ ->
          Lwt.return None
        end in
    Active_config.map parse_pcap string_pcap_settings
    >>= fun pcap_settings ->

    let bind_path = driver @ [ "allowed-bind-address" ] in
    Active_config.string_option config bind_path
    >>= fun string_allowed_bind_address ->
    let parse_bind_address = function
      | None -> Lwt.return None
      | Some x ->
        let strings = List.map String.trim @@ Stringext.split x ~on:',' in
        let ip_opts = List.map
          (fun x ->
            try
              Some (Ipaddr.of_string_exn x)
            with _ ->
              Log.err (fun f -> f "Failed to parse IP address in allowed-bind-address: %s" x);
              None
          ) strings in
        let ips = List.fold_left (fun acc x -> match x with None -> acc | Some x -> x :: acc) [] ip_opts in
        Lwt.return (Some ips) in
    Active_config.map parse_bind_address string_allowed_bind_address
    >>= fun allowed_bind_address ->

    let rec monitor_allowed_bind_settings allowed_bind_address =
      Forward.set_allowed_addresses (Active_config.hd allowed_bind_address);
      Active_config.tl allowed_bind_address
      >>= fun allowed_bind_address ->
      monitor_allowed_bind_settings allowed_bind_address in
    Lwt.async (fun () -> log_exception_continue "monitor_allowed_bind_settings" (fun () -> monitor_allowed_bind_settings allowed_bind_address));

    let peer_ips_path = driver @ [ "slirp"; "docker" ] in
    let parse_ipv4 default x = match Ipaddr.V4.of_string @@ String.trim x with
      | None ->
        Log.err (fun f -> f "Failed to parse IPv4 address '%s', using default of %s" x (Ipaddr.V4.to_string default));
        Lwt.return default
      | Some x -> Lwt.return x in
    let default_peer = "192.168.65.2" in
    let default_host = "192.168.65.1" in
    Active_config.string config ~default:default_peer peer_ips_path
    >>= fun string_peer_ips ->
    Active_config.map (parse_ipv4 (Ipaddr.V4.of_string_exn default_peer)) string_peer_ips
    >>= fun peer_ips ->
    Lwt.async (fun () -> restart_on_change "slirp/docker" Ipaddr.V4.to_string peer_ips);

    let host_ips_path = driver @ [ "slirp"; "host" ] in
    Active_config.string config ~default:default_host host_ips_path
    >>= fun string_host_ips ->
    Active_config.map (parse_ipv4 (Ipaddr.V4.of_string_exn default_host)) string_host_ips
    >>= fun host_ips ->
    Lwt.async (fun () -> restart_on_change "slirp/host" Ipaddr.V4.to_string host_ips);

    let peer_ip = Active_config.hd peer_ips in
    let local_ip = Active_config.hd host_ips in

    Log.info (fun f -> f "Creating slirp server pcap_settings:%s peer_ip:%s local_ip:%s"
      (print_pcap @@ Active_config.hd pcap_settings) (Ipaddr.V4.to_string peer_ip) (Ipaddr.V4.to_string local_ip)
    );
    let t = {
      peer_ip;
      local_ip;
      pcap_settings;
    } in
    Lwt.return t

  let connect t client =
      Vmnet.of_fd ~client_macaddr ~server_macaddr client
      >>= function
      | `Error (`Msg m) -> failwith m
      | `Ok x ->
        Log.debug (fun f -> f "accepted vmnet connection");

        let rec monitor_pcap_settings pcap_settings =
          ( match Active_config.hd pcap_settings with
            | None ->
              Log.debug (fun f -> f "Disabling any active packet capture");
              Vmnet.stop_capture x
            | Some (filename, size_limit) ->
              Log.debug (fun f -> f "Capturing packets to %s %s" filename (match size_limit with None -> "with no limit" | Some x -> Printf.sprintf "limited to %Ld bytes" x));
              Vmnet.start_capture x ?size_limit filename )
          >>= fun () ->
          Active_config.tl pcap_settings
          >>= fun pcap_settings ->
          monitor_pcap_settings pcap_settings in
        Lwt.async (fun () ->
          log_exception_continue "monitor_pcap_settings"
            (fun () ->
              monitor_pcap_settings t.pcap_settings
            )
          );
        connect x t.peer_ip t.local_ip

end

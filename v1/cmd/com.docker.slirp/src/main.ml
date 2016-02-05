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

(* HACK: need to tweak the tcp-ip API *)
let local_port = 8080

let src =
  let src = Logs.Src.create "usernet" ~doc:"Mirage TCP/IP <-> socket proxy" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let finally f g =
  Lwt.catch (fun () -> f () >>= fun r -> g () >>= fun () -> return r) (fun e -> g () >>= fun () -> fail e)

let main_t pcap_filename socket_path port_control_path =
  Logs.set_reporter (Logs_fmt.reporter ());
  Printexc.record_backtrace true;

  (* Start the 9P port forwarding server *)
  let module Ports = Active_list.Make(Forward) in
  let module Server = Server9p_unix.Make(Log9p_unix.Stdout)(Ports) in
  let fs = Ports.make () in
  Server.listen fs "unix" port_control_path
  >>= function
  | Result.Error (`Msg m) -> failwith m
  | Result.Ok server ->
    Lwt.async (fun () -> Server.serve_forever server);

  Lwt.catch
    (fun () -> Lwt_unix.unlink socket_path)
    (function
      | Unix.Unix_error(Unix.ENOENT, _, _) -> Lwt.return ()
      | e -> fail e)
  >>= fun () ->
  let s = Lwt_unix.socket Lwt_unix.PF_UNIX Lwt_unix.SOCK_STREAM 0 in
  Lwt_unix.bind s (Lwt_unix.ADDR_UNIX socket_path);
  Lwt_unix.listen s 5;
    let rec loop () =
      Lwt_unix.accept s
      >>= fun (client, _) ->
      Ppp.of_fd ?pcap_filename client
      >>= function
      | `Error (`Msg m) -> failwith m
      | `Ok x ->
        begin Tcpip_stack.connect x
          >>= function
          | `Error (`Msg m) -> failwith m
          | `Ok s ->
            Ports.set_context fs s;
            Tcpip_stack.listen_udpv4 s 53 (Dns_forward.input s);
            Ppp.add_listener x (
              fun buf ->
                match (Wire_structs.parse_ethernet_frame buf) with
                | Some (Some Wire_structs.IPv4, _, payload) ->
                  let src = Ipaddr.V4.of_int32 @@ Wire_structs.Ipv4_wire.get_ipv4_src payload in
                  let dst = Ipaddr.V4.of_int32 @@ Wire_structs.Ipv4_wire.get_ipv4_dst payload in
                  begin match Wire_structs.Ipv4_wire.(int_to_protocol @@ get_ipv4_proto payload) with
                    | Some `UDP ->
                      let udp = Cstruct.shift payload Wire_structs.Ipv4_wire.sizeof_ipv4 in
                      let src_port = Wire_structs.get_udp_source_port udp in
                      let dst_port = Wire_structs.get_udp_dest_port udp in
                      let length = Wire_structs.get_udp_length udp in
                      let payload = Cstruct.sub udp Wire_structs.sizeof_udp (length - Wire_structs.sizeof_udp) in
                      Log.info (fun f -> f "UDP %s:%d -> %s:%d len %d"
                                   (Ipaddr.V4.to_string src) src_port
                                   (Ipaddr.V4.to_string dst) dst_port
                                   length
                               );
                      (* We handle DNS on port 53 ourselves *)
                      if dst_port <> 53 then begin
                        let reply buf = Tcpip_stack.UDPV4.writev ~source_ip:dst ~source_port:dst_port ~dest_ip:src ~dest_port:src_port (Tcpip_stack.udpv4 s) [ buf ] in
                        Socket.UDPV4.input ~reply ~src:(src, src_port) ~dst:(dst, dst_port) ~payload
                      end else Lwt.return_unit
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
                Log.info (fun f -> f "%s connecting" description);

                Socket.TCPV4.connect_v4 src_ip src_port
                >>= function
                | `Error (`Msg m) ->
                  Log.info (fun f -> f "%s rejected: %s" description m);
                  return `Reject
                | `Ok remote ->
                  Lwt.return (`Accept (fun local ->
                      finally (fun () ->
                          (* proxy between local and remote *)
                          Log.info (fun f -> f "%s connected" description);
                          Mirage_flow.proxy (module Clock) (module Tcpip_stack.TCPV4_half_close) local (module Socket.TCPV4) remote ()
                          >>= function
                          | `Error (`Msg m) ->
                            Log.err (fun f -> f "%s proxy failed with %s" description m);
                            return ()
                          | `Ok (l_stats, r_stats) ->
                            Log.info (fun f ->
                                f "%s closing: l2r = %s; r2l = %s" description
                                  (Mirage_flow.CopyStats.to_string l_stats) (Mirage_flow.CopyStats.to_string r_stats)
                              );
                            return ()
                        ) (fun () ->
                          Socket.TCPV4.close remote
                          >>= fun () ->
                          Log.info (fun f -> f "%s Socket.TCPV4.close" description);
                          Lwt.return ()
                        )
                    ))
            );
            Tcpip_stack.listen s
            >>= fun () ->
            Log.info (fun f -> f "TCP/IP ready");
            loop ()
        end in
    loop ()

let main pcap_file socket control = Lwt_main.run @@ main_t pcap_file socket control

open Cmdliner

let pcap_file =
  Arg.(value & opt (some string) None & info [ "pcap" ] ~docv:"PCAP")

let socket =
  Arg.(value & opt string "/var/tmp/com.docker.slirp.socket" & info [ "socket" ] ~docv:"SOCKET")

let port_control_path =
  Arg.(value & opt string "/var/tmp/com.docker.slirp.port.socket" & info [ "port-control" ] ~docv:"PORT")

let command =
  let doc = "proxy TCP/IP connections from an ethernet link via sockets" in
  let man =
    [`S "DESCRIPTION";
     `P "Terminates TCP/IP and UDP/IP connections from a client and proxy the
		     flows via userspace sockets"]
  in
  Term.(pure main $ pcap_file $ socket $ port_control_path),
  Term.info "proxy" ~doc ~man

let () =
  Printexc.record_backtrace true;
  match Term.eval command with
  | `Error _ -> exit 1
  | _ -> exit 0

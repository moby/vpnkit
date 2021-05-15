open Lwt.Infix

let src =
  let src = Logs.Src.create "ICMP" ~doc:"ICMP NAT implementation" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

type reply = Cstruct.t -> unit Lwt.t

type address = Ipaddr.V4.t

type datagram = {
  src: address;
  dst: address;
  ty: int;
  code: int;
  seq: int;
  id: int;
  payload: Cstruct.t;
}

module Make
    (Sockets: Sig.SOCKETS)
    (Clock: Mirage_clock.MCLOCK)
    (Time: Mirage_time.S)
= struct

  module Icmp = Sockets.Datagram.Udp

  type key = Ipaddr.V4.t * int (* IP * ICMP ty *)

  (* An active ICMP "flow" *)
  type flow = {
    description: string;
    phys: key;
    virt: key;
    mutable last_use: int64;
  }

  module IntSet = Set.Make(struct type t = int let compare = compare end)

  type t = {
    server_fd: Unix.file_descr;
    server: Icmp.server;
    phys_to_flow: (key, flow) Hashtbl.t;
    virt_to_flow: (key, flow) Hashtbl.t;
    ids_in_use: IntSet.t ref;
    mutable next_id: int;
    mutable send_reply: (src:address -> dst:address -> payload:Cstruct.t -> unit Lwt.t) option;
  }

  let start_background_gc phys_to_flow virt_to_flow ids_in_use max_idle_time =
    let rec loop () =
      Time.sleep_ns max_idle_time >>= fun () ->
      let now_ns = Clock.elapsed_ns () in
      let to_shutdown =
        Hashtbl.fold (fun phys flow acc ->
            if Int64.(sub now_ns flow.last_use) > max_idle_time then begin
              Log.info (fun f ->
                  f "Hostnet_icmp %s: expiring ICMP NAT rule" flow.description);
              (phys, flow) :: acc
            end else acc
          ) phys_to_flow []
      in
      List.iter (fun (phys, flow) ->
        ids_in_use := IntSet.remove (snd flow.phys) !ids_in_use;
        Hashtbl.remove phys_to_flow phys;
        Hashtbl.remove virt_to_flow flow.virt;
      ) to_shutdown;
      loop () in
    loop ()

  (* Allocate a free physical id for a new "flow" *)
  let allocate_next_id t =
    let start = t.next_id in
    let in_use = !(t.ids_in_use) in
    let rec find from =
      if not(IntSet.mem from in_use) then begin
        t.ids_in_use := IntSet.add from in_use;
        t.next_id <- from;
        Some from
      end else begin
        let next = (from + 1) mod 0xffff in
        if next = start
        then None (* all are in use, we'll have to drop the packet *)
        else find next
      end in
    find start

  let is_win32 = Sys.os_type = "Win32"

  let sock_icmp =
    (* Windows uses SOCK_RAW protocol 1 for ICMP
      Unix uses SOCK_DGRAM protocol 1 for ICMP *)
    if is_win32 then Unix.SOCK_RAW else Unix.SOCK_DGRAM

  let ipproto_icmp = 1 (* according to BSD /etc/protocols *)
  let _port = 0 (* port isn't meaningful in this context *)

  let create ?(max_idle_time = Duration.(of_sec 60)) () =
    let phys_to_flow = Hashtbl.create 7 in
    let virt_to_flow = Hashtbl.create 7 in
    let server_fd = Unix.socket Unix.PF_INET sock_icmp ipproto_icmp in
    let server = Icmp.of_bound_fd server_fd in
    let ids_in_use = ref IntSet.empty in
    let next_id = 0 in
    let send_reply = None in
    let _background_gc_t = start_background_gc phys_to_flow virt_to_flow ids_in_use max_idle_time in
    { server; server_fd; phys_to_flow; virt_to_flow; ids_in_use; next_id; send_reply }

  let start_receiver t =
    let buf = Cstruct.create 4096 in

    let try_to_send ~src ~dst ~payload =
      match t.send_reply with
      | Some fn ->
        fn ~src ~dst ~payload
        >>= fun () ->
        Lwt.return true
      | None ->
        Log.warn (fun f -> f "dropping ICMP because reply callback not set");
        Lwt.return true in

    let rec loop () =
      Lwt.catch (fun () ->
        Icmp.recvfrom t.server buf
        >>= fun (n, _) ->
        let datagram = Cstruct.sub buf 0 n in
        (* On macOS the IP length field is set to a very large value (16384) which
           probably reflects some kernel datastructure size rather than the real
           on-the-wire size. This confuses our IPv4 parser so we correct the size
           here. *)
        let len = Ipv4_wire.get_ipv4_len datagram in
        Ipv4_wire.set_ipv4_len datagram (min len n);
        match Frame.ipv4 [ datagram ] with
        | Error (`Msg m) ->
          Log.err (fun f -> f "Error unmarshalling IP datagram: %s" m);
          Lwt.return_true
        | Ok { src; payload = Frame.Icmp { raw; icmp = Frame.Echo { id; _ }; _ }; _ } ->
          if Hashtbl.mem t.phys_to_flow (src, id) then begin
            let flow = Hashtbl.find t.phys_to_flow (src, id) in
            let id' = snd flow.virt in
            (* Rewrite the id in the Echo response *)
            Icmpv4_wire.set_icmpv4_id raw id';
            Icmpv4_wire.set_icmpv4_csum raw 0;
            Icmpv4_wire.set_icmpv4_csum raw (Tcpip_checksum.ones_complement raw);
            try_to_send ~src ~dst:(fst flow.virt) ~payload:raw
          end else begin
            Log.debug (fun f ->
              f "ICMP dropping (%a, %d) %a"
              Ipaddr.V4.pp src id Cstruct.hexdump_pp raw);
            Lwt.return_true
          end
        | Ok { src=src'; dst=dst'; payload = Frame.Icmp { raw = icmp_buffer; icmp = Frame.Time_exceeded { ipv4 = Ok { src; dst; raw = original_ipv4; payload = Frame.Icmp { raw = original_icmp; icmp = Frame.Echo { id; _ }; _ }; _ }; _ }; _ }; _ } ->
          (* This message comes from a router. We need to examine the nested packet to see
             where to forward it. *)
          if Hashtbl.mem t.phys_to_flow (dst, id) then begin
            (* Our only idea of the true destination is in the NAT table *)
            let flow = Hashtbl.find t.phys_to_flow (dst, id) in
            let id' = snd flow.virt in
            (* Rewrite the id in the nested original packet *)
            Icmpv4_wire.set_icmpv4_id original_icmp id';
            Icmpv4_wire.set_icmpv4_csum original_icmp 0;
            Icmpv4_wire.set_icmpv4_csum original_icmp (Tcpip_checksum.ones_complement original_icmp);
            (* Rewrite the src address to use the internal address *)
            let new_src = Ipaddr.V4.to_int32 @@ fst flow.virt in
            Ipv4_wire.set_ipv4_src original_ipv4 new_src;
            (* Note we don't recompute the IPv4 checksum since the packet is truncated *)
            Icmpv4_wire.set_icmpv4_csum icmp_buffer 0;
            Icmpv4_wire.set_icmpv4_csum icmp_buffer (Tcpip_checksum.ones_complement icmp_buffer);
            try_to_send ~src:src' ~dst:(fst flow.virt) ~payload:icmp_buffer
          end else begin
            Log.debug (fun f -> f "Dropping TTL exceeded src' = %a dst' = %a; src = %a; dst = %a; id = %d"
              Ipaddr.V4.pp src'
              Ipaddr.V4.pp dst'
              Ipaddr.V4.pp src
              Ipaddr.V4.pp dst
              id
            );
            Lwt.return_true
          end
        | Ok { src=src'; dst=dst'; payload = Frame.Icmp { raw = icmp_buffer; icmp = Frame.Time_exceeded { ipv4 = Ok { src; dst; raw = original_ipv4; payload = Frame.Udp { raw = original_udp; src = src_port; dst = dst_port; _ }; _ }; _ }; _ }; _ }
        | Ok { src=src'; dst=dst'; payload = Frame.Icmp { raw = icmp_buffer; icmp = Frame.Destination_unreachable { ipv4 = Ok { src; dst; raw = original_ipv4; payload = Frame.Udp { raw = original_udp; src = src_port; dst = dst_port; _ }; _ }; _ }; _ }; _ } ->
          (* src:src_port are host addresses. We need to discover the internal IP and port *)
          if Hashtbl.mem Hostnet_udp.external_to_internal src_port then begin
            match Hashtbl.find Hostnet_udp.external_to_internal src_port with
            | Ipaddr.V4 internal_src, internal_port ->
              (* Rewrite the src address on the IPv4 to use the internal address *)
              Ipv4_wire.set_ipv4_src original_ipv4 (Ipaddr.V4.to_int32 internal_src);
              (* Rewrite the src_port on the UDP to use the internal address *)
              Udp_wire.set_udp_source_port original_udp internal_port;
              Icmpv4_wire.set_icmpv4_csum icmp_buffer 0;
              Icmpv4_wire.set_icmpv4_csum icmp_buffer (Tcpip_checksum.ones_complement icmp_buffer);
              try_to_send ~src:src' ~dst:internal_src ~payload:icmp_buffer
            | _, _ ->
              Log.debug (fun f -> f "Dropping TTL exceeded from internal IPv6 address");
              Lwt.return_true
          end else begin
            Log.debug (fun f -> f "Dropping TTL exceeded src' = %a dst' = %a; src = %a:%d; dst = %a:%d"
              Ipaddr.V4.pp src'
              Ipaddr.V4.pp dst'
              Ipaddr.V4.pp src src_port
              Ipaddr.V4.pp dst dst_port
            );
            Lwt.return_true
          end
        | Ok { payload = Frame.Icmp { icmp = Frame.Time_exceeded { ipv4 = Error (`Msg m) }; _ }; _ } ->
          Log.err (fun f -> f "Failed to forward TTL exceeeded: failed to parse inner packet: %s" m);
          Lwt.return_true
        | Ok { payload = Frame.Icmp { icmp = Frame.Time_exceeded { ipv4 = Ok { src; dst; payload = Frame.Tcp { src = src_port; dst = dst_port; _ }; _ }; _ }; _ }; _ } ->
          (* TODO: implement for TCP *)
          Log.debug (fun f -> f "Dropping TTL exceeeded for TCP %a:%d -> %a%d"
            Ipaddr.V4.pp src src_port Ipaddr.V4.pp dst dst_port
          );
          Lwt.return_true
        | Ok { payload = Frame.Icmp { icmp = Frame.Time_exceeded _; _ }; _ } ->
          Log.debug (fun f -> f "Dropping TTL exceeded for non-ICMP/UDP/TCP");
          Lwt.return_true
        | Ok { payload = Frame.Icmp { icmp = Frame.Unknown_icmp { ty } ; _ }; _ } ->
          Log.err (fun f -> f "Failed to forward unexpected ICMP datagram with type %d" ty);
          Lwt.return_true
        | Ok _ ->
          Log.debug (fun f -> f "Failed to forward unexpected IPv4 datagram");
          Lwt.return_true
      ) (fun e ->
        Log.err (fun f ->
            f "Hostnet_icmp: caught unexpected exception %a"
              Fmt.exn e);
        Lwt.return false
      ) >>= function
      | false ->
        Lwt.return_unit
      | true -> loop () in
    Lwt.async loop

  let set_send_reply ~t ~send_reply =
    t.send_reply <- Some send_reply;
    start_receiver t

  let input ~t ~datagram:{src; dst; ty; code; id; seq; payload} ~ttl () =
    Log.debug (fun f ->
      f "ICMP received %a -> %a ttl=%d ty=%d code=%d id=%d seq=%d payload len %d"
        Ipaddr.V4.pp src Ipaddr.V4.pp dst
        ttl ty code id seq (Cstruct.len payload));
    match Icmpv4_wire.int_to_ty ty with
      | None ->
        Log.err (fun f -> f "Unknown ICMP type: %d" ty);
        Lwt.return_unit
      | Some ty ->
        let virt = src, id in
        let id =
          if Hashtbl.mem t.virt_to_flow virt then begin
            let flow = Hashtbl.find t.virt_to_flow virt in
            Some (snd flow.phys)
          end else allocate_next_id t in
        begin match id with
          | None ->
            Log.warn (fun f -> f "Dropping ICMP because we've run out of external ids");
            Lwt.return_unit
          | Some id' ->
            let phys = dst, id' in
            let description = Printf.sprintf "%s id=%d -> %s id=%d"
              (Ipaddr.V4.to_string @@ fst virt) (snd virt) (Ipaddr.V4.to_string @@ fst phys) (snd phys) in
            let last_use = Clock.elapsed_ns () in
            let flow = { description; virt; phys; last_use } in
            Hashtbl.replace t.phys_to_flow phys flow;
            Hashtbl.replace t.virt_to_flow virt flow;
            let req = Icmpv4_packet.({code; ty;
                                      subheader = Id_and_seq (id', seq)}) in
            let header = Icmpv4_packet.Marshal.make_cstruct req ~payload in
            let icmp = Cstruct.concat [ header; payload ] in
            Icmp.sendto t.server (Ipaddr.V4 dst, 0) ~ttl icmp
        end
end

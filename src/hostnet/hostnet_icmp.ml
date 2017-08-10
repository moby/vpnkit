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
    (Clock: Mirage_clock_lwt.MCLOCK)
    (Time: Mirage_time_lwt.S)
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
    clock: Clock.t;
    server: Icmp.server;
    phys_to_flow: (key, flow) Hashtbl.t;
    virt_to_flow: (key, flow) Hashtbl.t;
    ids_in_use: IntSet.t ref;
    mutable next_id: int;
    mutable send_reply: (src:address -> dst:address -> payload:Cstruct.t -> unit Lwt.t) option;
  }

  let start_background_gc clock phys_to_flow virt_to_flow ids_in_use max_idle_time =
    let rec loop () =
      Time.sleep_ns max_idle_time >>= fun () ->
      let now_ns = Clock.elapsed_ns clock in
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

  let create ?(max_idle_time = Duration.(of_sec 60)) clock =
    let phys_to_flow = Hashtbl.create 7 in
    let virt_to_flow = Hashtbl.create 7 in
    let fd = Unix.socket Unix.PF_INET sock_icmp ipproto_icmp in
    let server = Icmp.of_bound_fd fd in
    let ids_in_use = ref IntSet.empty in
    let next_id = 0 in
    let send_reply = None in
    let _background_gc_t = start_background_gc clock phys_to_flow virt_to_flow ids_in_use max_idle_time in
    { clock; server; phys_to_flow; virt_to_flow; ids_in_use; next_id; send_reply }

  let start_receiver t =
    let buf = Cstruct.create 4096 in
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
        match Ipv4_packet.Unmarshal.of_cstruct buf with
        | Error msg ->
          Log.err (fun f -> f "Error unmarshalling IP datagram: %s" msg);
          Lwt.return_true
        | Ok (ipv4, ip_payload) ->
          match Icmpv4_packet.Unmarshal.of_cstruct ip_payload with
          | Error msg ->
            Log.err (fun f -> f "Error unmarshalling ICMP message: %s" msg);
            Lwt.return_true
          | Ok (icmp, icmp_payload) ->
            let open Icmpv4_packet in
            begin match icmp.subheader with
            | Next_hop_mtu _ | Pointer _ | Address _ | Unused ->
              Log.debug (fun f ->
                f "received an ICMP message which wasn't an echo-request or reply: %a" Cstruct.hexdump_pp buf);
              Lwt.return true
            | Id_and_seq (id, seq) ->
              let ty = Icmpv4_wire.ty_to_int icmp.Icmpv4_packet.ty in
              let phys = ipv4.Ipv4_packet.src, id in
              if Hashtbl.mem t.phys_to_flow phys then begin
                let flow = Hashtbl.find t.phys_to_flow phys in
                let id' = snd flow.virt in
                let icmp' = { icmp with subheader = Id_and_seq(id', seq) } in
                let header = Marshal.make_cstruct icmp' ~payload:icmp_payload in
                let payload = Cstruct.concat [ header; icmp_payload ] in
                Log.debug (fun f ->
                  f "ICMP sending %a -> %a ty=%d code=%d id=%d seq=%d payload len %d"
                    Ipaddr.V4.pp_hum ipv4.Ipv4_packet.src Ipaddr.V4.pp_hum ipv4.Ipv4_packet.dst
                    ty icmp.Icmpv4_packet.code id seq
                    (Cstruct.len icmp_payload));
                match t.send_reply with
                | Some fn ->
                  fn ~src:ipv4.Ipv4_packet.src ~dst:(fst flow.virt) ~payload
                  >>= fun () ->
                  Lwt.return true
                | None ->
                  Log.warn (fun f -> f "dropping ICMP because reply callback not set");
                  Lwt.return true
              end else begin
                (* This happens when the host receives other ICMP which we're not listening for *)
                Log.info (fun f ->
                  f "ICMP dropping %a -> %a ty=%d code=%d id=%d seq=%d %a"
                    Ipaddr.V4.pp_hum ipv4.Ipv4_packet.src Ipaddr.V4.pp_hum ipv4.Ipv4_packet.dst
                    ty icmp.Icmpv4_packet.code id seq
                    Cstruct.hexdump_pp icmp_payload);
                Lwt.return true
              end
            end
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

  let input ~t ~datagram:{src; dst; ty; code; id; seq; payload} () =
    Log.debug (fun f ->
      f "ICMP received %a -> %a ty=%d code=%d id=%d seq=%d payload len %d"
        Ipaddr.V4.pp_hum src Ipaddr.V4.pp_hum dst
        ty code id seq (Cstruct.len payload));
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
            let last_use = Clock.elapsed_ns t.clock in
            let flow = { description; virt; phys; last_use } in
            Hashtbl.replace t.phys_to_flow phys flow;
            Hashtbl.replace t.virt_to_flow virt flow;
            let req = Icmpv4_packet.({code; ty;
                                      subheader = Id_and_seq (id', seq)}) in
            let header = Icmpv4_packet.Marshal.make_cstruct req ~payload in
            let icmp = Cstruct.concat [ header; payload ] in
            Icmp.sendto t.server (Ipaddr.V4 dst, 0) icmp
        end
end

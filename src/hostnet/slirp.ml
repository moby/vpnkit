open Lwt.Infix

let src =
  let src = Logs.Src.create "usernet" ~doc:"Mirage TCP/IP <-> socket proxy" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module IPMap = Map.Make(Ipaddr.V4)

(* When forwarding TCP, the connection is proxied so the MTU/MSS is
   link-local.  When forwarding UDP, the datagram on the internal link
   is the same size as the corresponding datagram on the external
   link, so we have to be careful to respect the Do Not Fragment
   bit. *)
let safe_outgoing_mtu = 1452 (* packets above this size with DNF set
                                will get ICMP errors *)

let log_exception_continue description f =
  Lwt.catch
    (fun () -> f ())
    (fun e ->
       Log.debug (fun f -> f "%s: caught %a" description Fmt.exn e);
       Lwt.return ()
    )

let failf fmt = Fmt.kstrf Lwt.fail_with fmt

let or_failwith name m =
  m >>= function
  | Error _ -> failf "Failed to connect %s device" name
  | Ok x  -> Lwt.return x

type pcap = (string * int64 option) option

let print_pcap = function
| None -> "disabled"
| Some (file, None) -> Fmt.strf "capturing to %s with no limit" file
| Some (file, Some limit) ->
  Fmt.strf "capturing to %s but limited to %Ld" file limit

type arp_table = {
  mutex: Lwt_mutex.t;
  mutable table: (Ipaddr.V4.t * Macaddr.t) list;
}

type uuid_table = {
  mutex: Lwt_mutex.t;
  table: (Uuidm.t, Ipaddr.V4.t * int) Hashtbl.t;
}

module Make
    (Vmnet: Sig.VMNET)
    (Dns_policy: Sig.DNS_POLICY)
    (Clock: sig
       include Mirage_clock_lwt.MCLOCK
       val connect: unit -> t Lwt.t
     end)
    (Random: Mirage_random.C)
    (Vnet : Vnetif.BACKEND with type macaddr = Macaddr.t) =
struct
  (* module Tcpip_stack = Tcpip_stack.Make(Vmnet)(Host.Time) *)

  type stack = {
    configuration: Configuration.t;
    global_arp_table: arp_table;
    client_uuids: uuid_table;
    vnet_switch: Vnet.t;
    clock: Clock.t;
  }

  module Filteredif = Filter.Make(Vmnet)
  module Netif = Capture.Make(Filteredif)
  module Recorder = (Netif: Sig.RECORDER with type t = Netif.t)
  module Switch = Mux.Make(Netif)
  module Dhcp = Hostnet_dhcp.Make(Clock)(Switch)

  (* This ARP implementation will respond to the VM: *)
  module Global_arp_ethif = Ethif.Make(Switch)
  module Global_arp = Arp.Make(Global_arp_ethif)

  (* This stack will attach to a switch port and represent a single remote IP *)
  module Stack_ethif = Ethif.Make(Switch.Port)
  module Stack_arpv4 = Arp.Make(Stack_ethif)
  module Stack_ipv4 = Static_ipv4.Make(Stack_ethif)(Stack_arpv4)
  module Stack_icmpv4 = Icmpv4.Make(Stack_ipv4)
  module Stack_tcp_wire = Tcp.Wire.Make(Stack_ipv4)
  module Stack_udp = Udp.Make(Stack_ipv4)(Random)
  module Stack_tcp = struct
    include Tcp.Flow.Make(Stack_ipv4)(Host.Time)(Clock)(Random)
    let shutdown_read _flow =
      (* No change to the TCP PCB: all this means is that I've
         got my finders in my ears and am nolonger listening to
         what you say. *)
      Lwt.return ()
    let shutdown_write = close
    (* Disable Nagle's algorithm *)
    let write = write_nodelay
  end

  module Dns_forwarder =
    Hostnet_dns.Make(Stack_ipv4)(Stack_udp)(Stack_tcp)(Host.Sockets)(Host.Dns)
      (Host.Time)(Clock)(Recorder)
  module Http_forwarder =
    Hostnet_http.Make(Stack_ipv4)(Stack_udp)(Stack_tcp)(Host.Sockets)(Host.Dns)

  module Udp_nat = Hostnet_udp.Make(Host.Sockets)(Clock)(Host.Time)
  module Icmp_nat = Hostnet_icmp.Make(Host.Sockets)(Clock)(Host.Time)
  
  let dns_forwarder ~local_address ~builtin_names clock =
    Dns_forwarder.create ~local_address ~builtin_names clock (Dns_policy.config ())

  (* Global variable containing the global DNS configuration *)
  let dns =
    let ip = Ipaddr.V4 Configuration.default_gateway_ip in
    let local_address = { Dns_forward.Config.Address.ip; port = 0 } in
    ref (
      Clock.connect () >>= fun clock ->
      dns_forwarder ~local_address ~builtin_names:[] clock
    )

  (* Global variable containing the global HTTP proxy configuration *)
  let http =
    ref None

  let is_dns = let open Frame in function
    | Ethernet { payload = Ipv4 { payload = Udp { src = 53; _ }; _ }; _ }
    | Ethernet { payload = Ipv4 { payload = Udp { dst = 53; _ }; _ }; _ }
    | Ethernet { payload = Ipv4 { payload = Tcp { src = 53; _ }; _ }; _ }
    | Ethernet { payload = Ipv4 { payload = Tcp { dst = 53; _ }; _ }; _ } ->
      true
    | _ -> false

  let is_ntp = let open Frame in function
    | Ethernet { payload = Ipv4 { payload = Udp { src = 123; _ }; _ }; _ }
    | Ethernet { payload = Ipv4 { payload = Udp { dst = 123; _ }; _ }; _ } ->
      true
    | _ -> false

  let is_icmp = let open Frame in function
    | Ethernet { payload = Ipv4 { payload = Icmp _; _ }; _ } -> true
    | _ -> false

  let is_http_proxy = let open Frame in function
    | Ethernet { payload = Ipv4 { payload = Tcp { src = (3128 | 3129); _ }; _ }; _ }
    | Ethernet { payload = Ipv4 { payload = Tcp { dst = (3128 | 3129); _ }; _ }; _ } ->
      true
    | _ -> false

  let string_of_id id =
    let src = Stack_tcp_wire.src id in
    let src_port = Stack_tcp_wire.src_port id in
    let dst = Stack_tcp_wire.dst id in
    let dst_port = Stack_tcp_wire.dst_port id in
    Fmt.strf "TCP %a:%d > %a:%d"
      Ipaddr.V4.pp dst dst_port
      Ipaddr.V4.pp src src_port

  module Tcp = struct

    module Id = struct
      module M = struct
        type t = Stack_tcp_wire.t
        let compare id1 id2 =
          let dst_ip1   = Stack_tcp_wire.dst id1 in
          let dst_port1 = Stack_tcp_wire.dst_port id1 in
          let dst_ip2   = Stack_tcp_wire.dst id2 in
          let dst_port2 = Stack_tcp_wire.dst_port id2 in
          let src_ip1   = Stack_tcp_wire.src id1 in
          let src_port1 = Stack_tcp_wire.src_port id1 in
          let src_ip2   = Stack_tcp_wire.src id2 in
          let src_port2 = Stack_tcp_wire.src_port id2 in
          let dst_ip'   = Ipaddr.V4.compare dst_ip1 dst_ip2 in
          let dst_port' = compare dst_port1 dst_port2 in
          let src_ip'   = Ipaddr.V4.compare src_ip1 src_ip2 in
          let src_port' = compare src_port1 src_port2 in
          if dst_port' <> 0
          then dst_port'
          else if dst_ip' <> 0
          then dst_ip'
          else if src_port' <> 0
          then src_port'
          else src_ip'
      end
      include M
      module Set = Set.Make(M)
      module Map = Map.Make(M)
    end

    module Flow = struct
      (** An established flow *)

      type t = {
        clock: Clock.t;
        id: Stack_tcp_wire.t;
        mutable socket: Host.Sockets.Stream.Tcp.flow option;
        mutable last_active_time_ns: int64;
      }

      (* Consider the case when a computer is sleep for several hours and then powered on.
         If we use the wall clock: we would conclude that all flows have been idle for hours
         and possibly terminate them.
         If we use a monotonic clock driven from a CPU counter: the clock will be paused while the
         computer is asleep so we will conclude the flows are still active. *)
      let idle_time t : Duration.t = Int64.sub (Clock.elapsed_ns t.clock) t.last_active_time_ns

      let to_string t =
        Printf.sprintf "%s socket = %s last_active = %s"
          (string_of_id t.id)
          (match t.socket with None -> "closed" | _ -> "open")
          (Duration.pp Format.str_formatter (idle_time t); Format.flush_str_formatter ())

      (* Global table of active flows *)
      let all : t Id.Map.t ref = ref Id.Map.empty

      let filesystem () =
        let flows = Id.Map.fold (fun _ t acc -> to_string t :: acc) !all [] in
        Vfs.File.ro_of_string (String.concat "\n" flows)

      let create clock id socket =
        let socket = Some socket in
        let last_active_time_ns = Clock.elapsed_ns clock in
        let t = { clock; id; socket; last_active_time_ns } in
        all := Id.Map.add id t !all;
        t
      let remove id =
        all := Id.Map.remove id !all
      let mem id = Id.Map.mem id !all
      let find id = Id.Map.find id !all
      let touch id =
        if Id.Map.mem id !all then begin
          let flow = Id.Map.find id !all in
          flow.last_active_time_ns <- Clock.elapsed_ns flow.clock
        end
    end
  end

  module Endpoint = struct

    type t = {
      recorder:                 Recorder.t;
      netif:                    Switch.Port.t;
      ethif:                    Stack_ethif.t;
      arp:                      Stack_arpv4.t;
      ipv4:                     Stack_ipv4.t;
      icmpv4:                   Stack_icmpv4.t;
      udp4:                     Stack_udp.t;
      tcp4:                     Stack_tcp.t;
      clock:                    Clock.t;
      mutable pending:          Tcp.Id.Set.t;
      mutable last_active_time_ns: int64;
      (* Used to shutdown connections when the endpoint is removed from the switch. *)
      mutable established:      Tcp.Id.Set.t;
    }
    (** A generic TCP/IP endpoint *)

    let touch t =
      t.last_active_time_ns <- Clock.elapsed_ns t.clock

    let idle_time t : Duration.t = Int64.sub (Clock.elapsed_ns t.clock) t.last_active_time_ns

    let create recorder switch arp_table ip mtu clock =
      let netif = Switch.port switch ip in
      Stack_ethif.connect ~mtu netif >>= fun ethif ->
      Stack_arpv4.connect ~table:arp_table ethif |>fun arp ->
      Stack_ipv4.connect
        ~ip
        ~gateway:None
        ~network:Ipaddr.V4.Prefix.global
        ethif arp
      >>= fun ipv4 ->
      Stack_icmpv4.connect ipv4 >>= fun icmpv4 ->
      Stack_udp.connect ipv4 >>= fun udp4 ->
      Stack_tcp.connect ipv4 clock >>= fun tcp4 ->

      let pending = Tcp.Id.Set.empty in
      let last_active_time_ns = Clock.elapsed_ns clock in
      let established = Tcp.Id.Set.empty in
      let tcp_stack =
        { recorder; netif; ethif; arp; ipv4; icmpv4; udp4; tcp4; pending;
          last_active_time_ns; clock; established }
      in
      Lwt.return tcp_stack

    (* close_flow is idempotent and may be called both from a regular RST/FIN and also
       from a concurrent switch port timeout *)
    let close_flow t ~id reason =
      Log.debug (fun f -> f "%s: close_flow" (string_of_id id));
      (* The flow might have been completely closed already *)
      if Tcp.Flow.mem id then begin
        let tcp = Tcp.Flow.find id in
        begin match reason with
        | `Port_disconnect ->
          Log.warn (fun f -> f "%s closing flow due to idle port disconnection" (string_of_id id))
        | `Reset ->
          Log.debug (fun f -> f "%s: closing flow due to TCP RST" (string_of_id id))
        | `Fin ->
          Log.debug (fun f -> f "%s: closing flow due to TCP FIN" (string_of_id id))
        end;
        Tcp.Flow.remove id;
        t.established <- Tcp.Id.Set.remove id t.established;
        begin match tcp.Tcp.Flow.socket with
        | Some socket ->
          (* Note this should cause the proxy to exit cleanly *)
          tcp.Tcp.Flow.socket <- None;
          Host.Sockets.Stream.Tcp.close socket
        | None ->
          (* If we have a Tcp.Flow still in the table, there should still be an
             active socket, otherwise the state has gotten out-of-sync *)
          Log.warn (fun f -> f "%s: no socket registered, possible socket leak" (string_of_id id));
          Lwt.return_unit
        end
      end else Lwt.return_unit

    let destroy t =
      let all = Tcp.Id.Set.fold (fun id acc -> id :: acc) t.established [] in
      Lwt_list.iter_s (fun id -> close_flow t ~id `Port_disconnect) all
      >>= fun () ->
      t.established <- Tcp.Id.Set.empty;
      Lwt.return_unit

    let intercept_tcp_syn t ~id ~syn on_syn_callback (buf: Cstruct.t) =
      if syn then begin
        if Tcp.Id.Set.mem id t.pending then begin
          (* This can happen if the `connect` blocks for a few seconds *)
          Log.debug (fun
                      f -> f "%s: connection in progress, ignoring duplicate \
                              SYN" (string_of_id id));
          Lwt.return_unit
        end else if Tcp.Flow.mem id then begin
          (* This can happen when receiving a retransmitted SYN.
             Simply drop it. In many cases, it will be recovered by
             our SYN+ACK retransmission. *)
          Log.debug (fun
                      f -> f "%s: old connection, ignoring duplicate \
                              SYN" (string_of_id id));
          Lwt.return_unit
        end else begin
          t.pending <- Tcp.Id.Set.add id t.pending;
          t.established <- Tcp.Id.Set.add id t.established;
          Lwt.finalize
            (fun () ->
               on_syn_callback ()
               >>= fun listeners ->
               let src = Stack_tcp_wire.dst id in
               let dst = Stack_tcp_wire.src id in
               Stack_tcp.input t.tcp4 ~listeners ~src ~dst buf
            ) (fun () ->
                t.pending <- Tcp.Id.Set.remove id t.pending;
                Lwt.return_unit;
              )
        end
      end else begin
        Tcp.Flow.touch id;
        (* non-SYN packets are injected into the stack as normal *)
        let src = Stack_tcp_wire.dst id in
        let dst = Stack_tcp_wire.src id in
        Stack_tcp.input t.tcp4 ~listeners:(fun _ -> None) ~src ~dst buf
      end

    module Proxy =
      Mirage_flow_lwt.Proxy(Clock)(Stack_tcp)(Host.Sockets.Stream.Tcp)

    let input_tcp t ~id ~syn ~rst (ip, port) (buf: Cstruct.t) =
      (* Note that we must cleanup even when the connection is reset before it
         is fully established. *)
      ( if rst
        then close_flow t ~id `Reset
        else Lwt.return_unit )
      >>= fun () ->
      intercept_tcp_syn t ~id ~syn (fun () ->
          Host.Sockets.Stream.Tcp.connect (ip, port)
          >>= function
          | Error (`Msg m) ->
            Log.debug (fun f ->
                f "%a:%d: failed to connect, sending RST: %s"
                  Ipaddr.pp ip port m);
            Lwt.return (fun _ -> None)
          | Ok socket ->
            let tcp = Tcp.Flow.create t.clock id socket in
            let listeners port =
              Log.debug (fun f ->
                  f "%a:%d handshake complete" Ipaddr.pp ip port);
              let f flow =
                match tcp.Tcp.Flow.socket with
                | None ->
                  Log.err (fun f ->
                      f "%s callback called on closed socket"
                        (Tcp.Flow.to_string tcp));
                  Lwt.return_unit
                | Some socket ->
                  Lwt.finalize (fun () ->
                    Proxy.proxy t.clock flow socket
                    >>= function
                    | Error e ->
                      Log.debug (fun f ->
                          f "%s proxy failed with %a"
                            (Tcp.Flow.to_string tcp) Proxy.pp_error e);
                      Lwt.return_unit
                    | Ok (_l_stats, _r_stats) ->
                      Lwt.return_unit
                  ) (fun () ->
                    Log.debug (fun f -> f "%s proxy terminated" (Tcp.Flow.to_string tcp));
                    close_flow t ~id `Fin
                  )
              in
              Some f
            in
            Lwt.return listeners
        ) buf

    (* Send an ICMP destination reachable message in response to the
       given packet. This can be used to indicate the packet would
       have been fragmented when the do-not-fragment flag is set. *)
    let send_icmp_dst_unreachable t ~src ~dst ~src_port ~dst_port ~ihl raw =
      let would_fragment ~ip_header ~ip_payload =
        let open Icmpv4_wire in
        let header = Cstruct.create sizeof_icmpv4 in
        set_icmpv4_ty header 0x03;
        set_icmpv4_code header 0x04;
        set_icmpv4_csum header 0x0000;
        (* this field is unused for icmp destination unreachable *)
        set_icmpv4_id header 0x00;
        set_icmpv4_seq header safe_outgoing_mtu;
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
      let ethernet_frame, len =
        Stack_ipv4.allocate_frame t.ipv4 ~dst:src ~proto:`ICMP
      in
      let ethernet_ip_hdr = Cstruct.sub ethernet_frame 0 len in

      let reply = would_fragment
          ~ip_header:(Cstruct.sub raw 0 (ihl * 4))
          ~ip_payload:(Some (Cstruct.sub raw (ihl * 4) 8)) in
      (* Rather than silently unset the do not fragment bit, we
         respond with an ICMP error message which will
         hopefully prompt the other side to send messages we
         can forward *)
      Log.err (fun f -> f
                  "Sending icmp-dst-unreachable in response to UDP %s:%d -> \
                   %s:%d with DNF set IPv4 len %d"
                  (Ipaddr.V4.to_string src) src_port
                  (Ipaddr.V4.to_string dst) dst_port
                  len);
      Stack_ipv4.writev t.ipv4 ethernet_ip_hdr [ reply ];
  end

  type connection = {
    vnet_client_id: Vnet.id;
    after_disconnect: unit Lwt.t;
    interface: Netif.t;
    switch: Switch.t;
    mutable endpoints: Endpoint.t IPMap.t;
    endpoints_m: Lwt_mutex.t;
    udp_nat: Udp_nat.t;
    icmp_nat: Icmp_nat.t option;
    all_traffic: Netif.rule;
  }

  let after_disconnect t = t.after_disconnect

  open Frame

  let pp_error ppf = function
  | `Udp e  -> Stack_udp.pp_error ppf e
  | `Ipv4 e -> Stack_ipv4.pp_error ppf e

  let lift_ipv4_error = function
  | Ok _ as x -> x
  | Error e   -> Error (`Ipv4 e)

  let lift_udp_error = function
  | Ok _ as x -> x
  | Error e   -> Error (`Udp e)

  let ok () = Ok ()

  module Localhost = struct
    type t = {
      clock: Clock.t;
      endpoint: Endpoint.t;
      udp_nat: Udp_nat.t;
      dns_ips: Ipaddr.t list;
    }
    (** Proxies connections to services on localhost on the host *)

    (** Handle IPv4 datagrams by proxying them to a remote system *)
    let input_ipv4 t ipv4 = match ipv4 with

    (* Respond to ICMP *)
    | Ipv4 { raw; payload = Icmp _; _ } ->
      let none ~src:_ ~dst:_ _ = Lwt.return_unit in
      let default ~proto ~src ~dst buf = match proto with
      | 1 (* ICMP *) ->
        Stack_icmpv4.input t.endpoint.Endpoint.icmpv4 ~src ~dst buf
      | _ ->
        Lwt.return_unit in
      Stack_ipv4.input t.endpoint.Endpoint.ipv4 ~tcp:none ~udp:none ~default raw
      >|= ok

    (* UDP to localhost *)
    | Ipv4 { src; dst; ihl; dnf; raw; ttl;
             payload = Udp { src = src_port; dst = dst_port; len;
                             payload = Payload payload; _ }; _ } ->
      let description =
        Fmt.strf "%a:%d -> %a:%d" Ipaddr.V4.pp src src_port Ipaddr.V4.pp
          dst dst_port
      in
      if Cstruct.len payload < len then begin
        Log.err (fun f -> f "%s: dropping because reported len %d actual len %d"
                    description len (Cstruct.len payload));
        Lwt.return (Ok ())
      end else if dnf && (Cstruct.len payload > safe_outgoing_mtu) then begin
        Endpoint.send_icmp_dst_unreachable t.endpoint ~src ~dst ~src_port
          ~dst_port ~ihl raw
        >|= lift_ipv4_error
      end else begin
        (* [1] For UDP to our local address, rewrite the destination
           to localhost.  This is the inverse of the rewrite
           below[2] *)
        let datagram =
          { Hostnet_udp.src = Ipaddr.V4 src, src_port;
            dst = Ipaddr.(V4 V4.localhost), dst_port;
            intercept = Ipaddr.(V4 V4.localhost), dst_port;
            payload }
        in
        Udp_nat.input ~t:t.udp_nat ~datagram ~ttl ()
        >|= ok
      end

    (* TCP to local ports *)
    | Ipv4 { src; dst;
             payload = Tcp { src = src_port; dst = dst_port; syn; rst; raw;
                             payload = Payload _; _ }; _ } ->
      let id =
        Stack_tcp_wire.v ~src_port:dst_port ~dst:src ~src:dst ~dst_port:src_port
      in
      Endpoint.input_tcp t.endpoint ~id ~syn ~rst
        (Ipaddr.V4 Ipaddr.V4.localhost, dst_port) raw
      >|= ok
    | _ ->
      Lwt.return (Ok ())

    let create clock endpoint udp_nat dns_ips =
      let tcp_stack = { clock; endpoint; udp_nat; dns_ips } in
      let open Lwt.Infix in
      (* Wire up the listeners to receive future packets: *)
      Switch.Port.listen endpoint.Endpoint.netif
        (fun buf ->
           let open Frame in
           match parse [ buf ] with
           | Ok (Ethernet { payload = Ipv4 ipv4; _ }) ->
             Endpoint.touch endpoint;
             (input_ipv4 tcp_stack (Ipv4 ipv4) >|= function
               | Ok ()   -> ()
               | Error e ->
                 Log.err (fun l ->
                     l "error while reading IPv4 input: %a" pp_error e))
           | _ ->
             Lwt.return_unit
        )
      >|= function
      | Ok ()         -> Ok tcp_stack
      | Error _ as e -> e

  end

  module Gateway = struct
    type t = {
      clock: Clock.t;
      endpoint: Endpoint.t;
      udp_nat: Udp_nat.t;
      dns_ips: Ipaddr.V4.t list;
      localhost_names: Dns.Name.t list;
      localhost_ips: Ipaddr.t list;
    }
    (** Services offered by vpnkit to the internal network *)

    let input_ipv4 t ipv4 = match ipv4 with

    (* Respond to ICMP *)
    | Ipv4 { raw; payload = Icmp _; _ } ->
      let none ~src:_ ~dst:_ _ = Lwt.return_unit in
      let default ~proto ~src ~dst buf = match proto with
      | 1 (* ICMP *) ->
        Stack_icmpv4.input t.endpoint.Endpoint.icmpv4 ~src ~dst buf
      | _ ->
        Lwt.return_unit in
      Stack_ipv4.input t.endpoint.Endpoint.ipv4 ~tcp:none ~udp:none ~default raw
      >|= ok

    (* UDP to forwarded elsewhere *)
    | Ipv4 { src; dst; ttl;
             payload = Udp { src = src_port; dst = dst_port;
                             payload = Payload payload; _ }; _ } when Gateway_forwards.Udp.mem dst_port ->
      let intercept_ipv4, intercept_port = Gateway_forwards.Udp.find dst_port in
      let datagram =
      { Hostnet_udp.src = Ipaddr.V4 src, src_port;
        dst = Ipaddr.V4 dst, dst_port;
        intercept = Ipaddr.V4 intercept_ipv4, intercept_port; payload }
      in
      (* Need to use a different UDP NAT with a different reply IP address *)
      Udp_nat.input ~t:t.udp_nat ~datagram ~ttl ()
      >|= ok

    (* TCP to be forwarded elsewhere *)
    | Ipv4 { src; dst;
             payload = Tcp { src = src_port; dst = dst_port; syn; rst; raw;
                             payload = Payload _; _ }; _ } when Gateway_forwards.Tcp.mem dst_port ->
      let id =
        Stack_tcp_wire.v ~src_port:dst_port ~dst:src ~src:dst ~dst_port:src_port
      in
      let forward_ip, forward_port = Gateway_forwards.Tcp.find dst_port in
      Endpoint.input_tcp t.endpoint ~id ~syn ~rst
        (Ipaddr.V4 forward_ip, forward_port) raw
      >|= ok

    (* UDP on port 53 -> DNS forwarder *)
    | Ipv4 { src; dst;
             payload = Udp { src = src_port; dst = 53;
                             payload = Payload payload; _ }; _ } ->
      let udp = t.endpoint.Endpoint.udp4 in
      !dns >>= fun t ->
      Dns_forwarder.handle_udp ~t ~udp ~src ~dst ~src_port payload
      >|= lift_udp_error

    (* TCP to port 53 -> DNS forwarder *)
    | Ipv4 { src; dst;
             payload = Tcp { src = src_port; dst = 53; syn; raw;
                             payload = Payload _; _ }; _ } ->
      let id =
        Stack_tcp_wire.v ~src_port:53 ~dst:src ~src:dst ~dst_port:src_port
      in
      Endpoint.intercept_tcp_syn t.endpoint ~id ~syn (fun () ->
          !dns >>= fun t ->
          Dns_forwarder.handle_tcp ~t
        ) raw
      >|= ok

    (* HTTP proxy *)
    | Ipv4 { src; dst;
             payload = Tcp { src = src_port; dst = dst_port; syn; raw;
                             payload = Payload _; _ }; _ } ->
      let id =
        Stack_tcp_wire.v ~src_port:dst_port ~dst:src ~src:dst ~dst_port:src_port
      in
      begin match !http with
      | None -> Lwt.return (Ok ())
      | Some http ->
        begin match Http_forwarder.explicit_proxy_handler ~localhost_names:t.localhost_names ~localhost_ips:t.localhost_ips ~dst:(dst, dst_port) ~t:http with
        | None -> Lwt.return (Ok ())
        | Some cb ->
          Endpoint.intercept_tcp_syn t.endpoint ~id ~syn (fun _ -> cb) raw
          >|= ok
        end
      end

    | _ ->
      Lwt.return (Ok ())

    let create clock endpoint udp_nat dns_ips localhost_names localhost_ips =
      let tcp_stack = { clock; endpoint; udp_nat; dns_ips; localhost_names; localhost_ips } in
      let open Lwt.Infix in
      (* Wire up the listeners to receive future packets: *)
      Switch.Port.listen endpoint.Endpoint.netif
        (fun buf ->
           let open Frame in
           match parse [ buf ] with
           | Ok (Ethernet { payload = Ipv4 ipv4; _ }) ->
             Endpoint.touch endpoint;
             (input_ipv4 tcp_stack (Ipv4 ipv4) >|= function
               | Ok ()   -> ()
               | Error e ->
                 Log.err (fun l ->
                     l "error while reading IPv4 input: %a" pp_error e))
           | _ ->
             Lwt.return_unit
        )
      >|= function
      | Ok ()         -> Ok tcp_stack
      | Error _ as e -> e

  end

  module Remote = struct

    type t = {
      endpoint:        Endpoint.t;
      udp_nat:         Udp_nat.t;
      icmp_nat:        Icmp_nat.t option;
      localhost_names: Dns.Name.t list;
      localhost_ips:   Ipaddr.t list;
    }
    (** Represents a remote system by proxying data to and from sockets *)

    (** Handle IPv4 datagrams by proxying them to a remote system *)
    let input_ipv4 t ipv4 = match ipv4 with

    (* Respond to ICMP ECHO *)
    | Ipv4 { src; dst; ttl; payload = Icmp { ty; code; icmp = Echo { id; seq; payload }; _ }; _ } ->
      let datagram = {
        Hostnet_icmp.src = src; dst = dst;
        ty; code; seq; id; payload
      } in
      ( match t.icmp_nat with
        | Some icmp_nat ->
          Icmp_nat.input ~t:icmp_nat ~datagram ~ttl ()
          >|= ok
        | None ->
          Lwt.return (Ok ()) )

    (* Transparent HTTP intercept? *)
    | Ipv4 { src = dest_ip ; dst = local_ip;
             payload = Tcp { src = dest_port;
                             dst = local_port; syn; rst; raw; _ }; _ } ->
      let id =
        Stack_tcp_wire.v
          ~src_port:local_port ~dst:dest_ip ~src:local_ip ~dst_port:dest_port
      in
      let callback = match !http with
      | None -> None
      | Some http -> Http_forwarder.transparent_proxy_handler ~localhost_names:t.localhost_names ~localhost_ips:t.localhost_ips ~dst:(local_ip, local_port) ~t:http
      in
      begin match callback with
      | None ->
        Endpoint.input_tcp t.endpoint ~id ~syn ~rst (Ipaddr.V4 local_ip, local_port)
          raw (* common case *)
        >|= ok
      | Some cb ->
        Endpoint.intercept_tcp_syn t.endpoint ~id ~syn (fun _ -> cb) raw
        >|= ok
      end
    | Ipv4 { src; dst; ihl; dnf; raw; ttl;
             payload = Udp { src = src_port; dst = dst_port; len;
                             payload = Payload payload; _ }; _ } ->
      let description = Printf.sprintf "%s:%d -> %s:%d"
          (Ipaddr.V4.to_string src) src_port (Ipaddr.V4.to_string dst) dst_port in
      if Cstruct.len payload < len then begin
        Log.err (fun f ->
            f "%s: dropping because reported len %d actual len %d"
              description len (Cstruct.len payload));
        Lwt_result.return ()
      end else if dnf && (Cstruct.len payload > safe_outgoing_mtu) then begin
        Endpoint.send_icmp_dst_unreachable t.endpoint ~src ~dst ~src_port
          ~dst_port ~ihl raw
      end else begin
        let datagram =
          { Hostnet_udp.src = Ipaddr.V4 src, src_port;
            dst = Ipaddr.V4 dst, dst_port;
            intercept = Ipaddr.V4 dst, dst_port;
            payload }
        in
        Udp_nat.input ~t:t.udp_nat ~datagram ~ttl ()
        >|= ok
      end

    | _ -> Lwt_result.return ()

    let create endpoint udp_nat icmp_nat localhost_names localhost_ips =
      let tcp_stack = { endpoint; udp_nat; icmp_nat; localhost_names; localhost_ips } in
      let open Lwt.Infix in
      (* Wire up the listeners to receive future packets: *)
      Switch.Port.listen endpoint.Endpoint.netif
        (fun buf ->
           let open Frame in
           match parse [ buf ] with
           | Ok (Ethernet { payload = Ipv4 ipv4; _ }) ->
             Endpoint.touch endpoint;
             (input_ipv4 tcp_stack (Ipv4 ipv4) >|= function
               | Ok ()   -> ()
               | Error e ->
                 Log.err (fun l ->
                     l "error while reading IPv4 input: %a"
                       Stack_ipv4.pp_error e))
           | _ ->
             Lwt.return_unit
        )
      >|= function
      | Ok ()        -> Ok tcp_stack
      | Error _ as e -> e
  end

  let filesystem t =
    let endpoints =
      let xs =
        IPMap.fold
          (fun ip t acc ->
             Fmt.strf "%a last_active_time = %s"
               Ipaddr.V4.pp ip
               (Duration.pp Format.str_formatter (Endpoint.idle_time t); Format.flush_str_formatter ())
             :: acc
          ) t.endpoints [] in
      Vfs.File.ro_of_string (String.concat "\n" xs) in
    Vfs.Dir.of_list
      (fun () ->
         Vfs.ok [
           (* could replace "connections" with "flows" *)
           Vfs.Inode.file "connections" (Host.Sockets.connections ());
           Vfs.Inode.dir "capture" @@ Netif.filesystem t.interface;
           Vfs.Inode.file "flows" (Tcp.Flow.filesystem ());
           Vfs.Inode.file "endpoints" endpoints;
           Vfs.Inode.file "ports" @@ Switch.filesystem t.switch;
         ]
      )

  let pcap t flow =
    let module C = Mirage_channel_lwt.Make(Host.Sockets.Stream.Unix) in
    let c = C.create flow in
    let stream = Netif.to_pcap t.all_traffic in
    let rec loop () =
      Lwt_stream.get stream
      >>= function
      | None ->
        Lwt.return_unit
      | Some bufs ->
        List.iter (C.write_buffer c) bufs;
        C.flush c
        >>= function
        | Ok ()   -> loop ()
        | Error e ->
          Log.err (fun l ->
            l "error while writing pcap dump: %a" C.pp_write_error e);
          Lwt.return_unit in
    loop ()

  let diagnostics t flow =
    let module C = Mirage_channel_lwt.Make(Host.Sockets.Stream.Unix) in
    let module Writer = Tar.HeaderWriter(Lwt)(struct
        type out_channel = C.t
        type 'a t = 'a Lwt.t
        let really_write oc buf =
          C.write_buffer oc buf;
          C.flush oc >|= function
          | Ok ()   -> ()
          | Error e ->
            Log.err (fun l ->
                l "error while flushing tar channel: %a" C.pp_write_error e)
      end) in
    let c = C.create flow in

    (* Operator which logs Vfs errors and returns *)
    let (>>?=) m f = m >>= function
      | Ok x -> f x
      | Error err ->
        Log.err (fun l -> l "diagnostics error: %a" Vfs.Error.pp err);
        Lwt.return_unit in

    let rec tar pwd dir =
      let mod_time = Int64.of_float @@ Unix.gettimeofday () in
      Vfs.Dir.ls dir
      >>?= fun inodes ->
      Lwt_list.iter_s
        (fun inode ->
           match Vfs.Inode.kind inode with
           | `Dir dir ->
             tar (Filename.concat pwd @@ Vfs.Inode.basename inode) dir
           | `File file ->
             (* Buffer the whole file temporarily in memory so we can
                calculate the exact length needed by the tar
                header. Note the `stat` won't be accurate because the
                file can change after we open it.  If there was an
                `fstat` API this could be fixed. *)
             Vfs.File.open_ file
             >>?= fun fd ->
             let copy () =
               let fragments = ref [] in
               let rec aux offset =
                 let count = 1048576 in
                 Vfs.File.read fd ~offset ~count
                 >>?= fun buf ->
                 fragments := buf :: !fragments;
                 let len = Int64.of_int @@ Cstruct.len buf in
                 if len = 0L
                 then Lwt.return_unit
                 else aux (Int64.add offset len) in
               aux 0L
               >>= fun () ->
               Lwt.return (List.rev !fragments)
             in
             copy ()
             >>= fun fragments ->
             let length =
               List.fold_left (+) 0 (List.map Cstruct.len fragments)
             in
             let header =
               Tar.Header.make ~file_mode:0o0644 ~mod_time
                 (Filename.concat pwd @@ Vfs.Inode.basename inode)
                 (Int64.of_int length)
             in
             Writer.write header c
             >>= fun () ->
             List.iter (C.write_buffer c) fragments;
             C.write_buffer c (Tar.Header.zero_padding header);
             C.flush c >|= function
             | Ok ()   -> ()
             | Error e ->
               Log.err (fun l ->
                   l "flushing of tar block failed: %a" C.pp_write_error e);
        ) inodes
    in
    tar "" (filesystem t)
    >>= fun () ->
    C.write_buffer c Tar.Header.zero_block;
    C.write_buffer c Tar.Header.zero_block;
    C.flush c >|= function
    | Ok ()   -> ()
    | Error e ->
      Log.err (fun l ->
          l "error while flushing the diagnostic: %a" C.pp_write_error e)

  module Debug = struct
    module Nat = struct
      include Udp_nat.Debug
      let get_table t = get_table t.udp_nat
      let get_max_active_flows t = get_max_active_flows t.udp_nat
    end
    let update_dns
        ?(local_ip = Ipaddr.V4 Ipaddr.V4.localhost) ?(builtin_names = []) clock
      =
      let local_address =
        { Dns_forward.Config.Address.ip = local_ip; port = 0 }
      in
      dns := dns_forwarder ~local_address ~builtin_names clock

    let update_http ?http:http_config ?https ?exclude ?transparent_http_ports ?transparent_https_ports () =
      Http_forwarder.create ?http:http_config ?https ?exclude ?transparent_http_ports ?transparent_https_ports ()
      >>= function
      | Error e -> Lwt.return (Error e)
      | Ok h ->
        http := Some h;
        Lwt.return (Ok ())

    let update_http_json j () =
      Http_forwarder.of_json j
      >>= function
      | Error e -> Lwt.return (Error e)
      | Ok h ->
        http := Some h;
        Lwt.return (Ok ())
  end

  (* If no traffic is received for `port_max_idle_time`, delete the endpoint and
     the switch port. *)
  let rec delete_unused_endpoints t ~port_max_idle_time () =
    if port_max_idle_time <= 0
    then Lwt.return_unit (* never delete a port *)
    else begin
      Host.Time.sleep_ns (Duration.of_sec 30)
      >>= fun () ->
      let max_age = Duration.of_sec port_max_idle_time in
      Lwt_mutex.with_lock t.endpoints_m
        (fun () ->
          let old_ips = IPMap.fold (fun ip endpoint acc ->
              let idle_time = Endpoint.idle_time endpoint in
              if idle_time > max_age then begin
                Log.info (fun f -> f "expiring endpoint %s with idle time %s > %s"
                  (Ipaddr.V4.to_string ip)
                  (Duration.pp Format.str_formatter idle_time; Format.flush_str_formatter ())
                  (Duration.pp Format.str_formatter max_age; Format.flush_str_formatter ())
                );
                (ip, endpoint) :: acc
              end else acc
            ) t.endpoints [] in
          Lwt_list.iter_s (fun (ip, endpoint) ->
              Switch.remove t.switch ip;
              t.endpoints <- IPMap.remove ip t.endpoints;
              Endpoint.destroy endpoint
            ) old_ips
        )
      >>= fun () ->
      delete_unused_endpoints t ~port_max_idle_time ()
    end

  let connect x vnet_switch vnet_client_id client_macaddr
      c (global_arp_table:arp_table) clock
    =

    let valid_subnets = [ Ipaddr.V4.Prefix.global ] in
    let valid_sources = [ Ipaddr.V4.of_string_exn "0.0.0.0" ] in

    Filteredif.connect ~valid_subnets ~valid_sources x
    |> fun (filteredif: Filteredif.t) ->
    Netif.connect filteredif
    |> fun interface ->
    Dns_forwarder.set_recorder interface;

    let kib = 1024 in
    (* Capture 256 KiB of all traffic *)
    let all_traffic = Netif.add_match ~t:interface ~name:"all.pcap" ~limit:(256 * kib)
      ~snaplen:c.Configuration.pcap_snaplen ~predicate:(fun _ -> true) in
    (* Capture 256 KiB of DNS traffic *)
    let (_: Netif.rule) = Netif.add_match ~t:interface ~name:"dns.pcap" ~limit:(256 * kib)
      ~snaplen:1500 ~predicate:is_dns in
    (* Capture 64KiB of NTP traffic *)
    let (_: Netif.rule) = Netif.add_match ~t:interface ~name:"ntp.pcap" ~limit:(64 * kib)
      ~snaplen:1500 ~predicate:is_ntp in
    (* Capture 8KiB of ICMP traffic *)
    let (_: Netif.rule) = Netif.add_match ~t:interface ~name:"icmp.pcap" ~limit:(8 * kib)
      ~snaplen:1500 ~predicate:is_icmp in
    let (_: Netif.rule) = Netif.add_match ~t:interface ~name:"http_proxy.pcap" ~limit:(1024 * kib)
      ~snaplen:1500 ~predicate:is_http_proxy in
    or_failwith "Switch.connect" (Switch.connect interface)
    >>= fun switch ->

    (* Serve a static ARP table *)
    let local_arp_table =
      (c.Configuration.lowest_ip, client_macaddr)
      :: (c.Configuration.gateway_ip, c.Configuration.server_macaddr)
      :: (if Ipaddr.V4.(compare unspecified c.Configuration.host_ip = 0) then [] else [ c.Configuration.host_ip, c.Configuration.server_macaddr])
    in
    Global_arp_ethif.connect switch
    >>= fun global_arp_ethif ->

    let dhcp = Dhcp.make ~configuration:c clock switch in

    let endpoints = IPMap.empty in
    let endpoints_m = Lwt_mutex.create () in
    let udp_nat = Udp_nat.create clock in
    let icmp_nat = match Icmp_nat.create clock with
      | icmp_nat -> Some icmp_nat
      | exception Unix.Unix_error (Unix.EPERM, _, _) ->
        Log.err (fun f -> f "Permission denied setting up user-space ICMP socket: ping will not work");
        None
      | exception e ->
        Log.err (fun f -> f "Unexpected exception %s setting up user-space ICMP socket: ping will not work" (Printexc.to_string e));
        None in
    let t = {
      vnet_client_id;
      after_disconnect = Vmnet.after_disconnect x;
      interface;
      switch;
      endpoints;
      endpoints_m;
      udp_nat;
      icmp_nat;
      all_traffic;
    } in
    Lwt.async @@ delete_unused_endpoints ~port_max_idle_time:c.Configuration.port_max_idle_time t;

    let find_endpoint ip =
      Lwt_mutex.with_lock t.endpoints_m
        (fun () ->
           if IPMap.mem ip t.endpoints
           then Lwt.return (Ok (IPMap.find ip t.endpoints))
           else begin
             Endpoint.create interface switch local_arp_table ip c.Configuration.mtu clock
             >|= fun endpoint ->
             t.endpoints <- IPMap.add ip endpoint t.endpoints;
             Ok endpoint
           end
        ) in

    (* Send a UDP datagram *)
    let send_reply = function
    | { Hostnet_udp.src = Ipaddr.V4 src, src_port;
        dst = Ipaddr.V4 dst, dst_port; payload; _ } ->
      (* [2] If the source address is localhost on the Mac, rewrite it to the
         virtual IP. This is the inverse of the rewrite above[1] *)
      let src =
        if Ipaddr.V4.compare src Ipaddr.V4.localhost = 0
        then c.Configuration.host_ip
        else src in
      begin
        find_endpoint src >>= function
        | Error (`Msg m) ->
          Log.err (fun f ->
              f "Failed to create an endpoint for %a: %s" Ipaddr.V4.pp dst m);
          Lwt.return_unit
        | Ok endpoint ->
          Stack_udp.write ~src_port ~dst ~dst_port endpoint.Endpoint.udp4 payload
          >|= function
          | Error e ->
            Log.err (fun f ->
                f "Failed to write a UDP packet: %a" Stack_udp.pp_error e);
          | Ok () -> ()
      end
    | { Hostnet_udp.src = src, src_port; dst = dst, dst_port; _ } ->
      Log.err (fun f ->
          f "Failed to send non-IPv4 UDP datagram %a:%d -> %a:%d"
            Ipaddr.pp src src_port Ipaddr.pp dst dst_port);
      Lwt.return_unit in

    Udp_nat.set_send_reply ~t:udp_nat ~send_reply;

    (* Send an ICMP datagram *)
    let send_reply ~src ~dst ~payload =
      find_endpoint src >>= function
      | Error (`Msg m) ->
          Log.err (fun f ->
              f "Failed to create an endpoint for %a: %s" Ipaddr.V4.pp dst m);
          Lwt.return_unit
      | Ok endpoint ->
        let ipv4 = endpoint.Endpoint.ipv4 in
        let buf, n = Stack_ipv4.allocate_frame ~dst ~proto:`ICMP ipv4 in
        let ip_header = Cstruct.sub buf 0 n in
        Stack_ipv4.write ipv4 ip_header payload
        >|= function
        | Error e ->
          Log.err (fun f ->
              f "Failed to write an IPv4 packet: %a" Stack_ipv4.pp_error e);
        | Ok () -> () in
    ( match icmp_nat with
      | Some icmp_nat -> Icmp_nat.set_send_reply ~t:icmp_nat ~send_reply
      | None -> () );

    (* If using bridge, add listener *)
    Vnet.set_listen_fn vnet_switch t.vnet_client_id (fun buf ->
        match parse [ buf ] with
        | Ok (Ethernet { src = eth_src ; dst = eth_dst ; _ }) ->
          Log.debug (fun f ->
              f "%d: received from bridge %s->%s, sent to switch.write"
                vnet_client_id
                (Macaddr.to_string eth_src)
                (Macaddr.to_string eth_dst));
          (Switch.write switch buf >|= function
            | Ok ()   -> ()
            | Error e ->
              Log.err (fun l -> l "switch write failed: %a" Switch.pp_error e))
        (* write packets from virtual network directly to client *)
        | _ -> Lwt.return_unit );

    (* Add a listener which looks for new flows *)
    Log.info (fun f ->
        f "Client mac: %s server mac: %s"
          (Macaddr.to_string client_macaddr) (Macaddr.to_string c.Configuration.server_macaddr));
    Switch.listen switch (fun buf ->
        let open Frame in
        match parse [ buf ] with
        | Ok (Ethernet { src = eth_src ; dst = eth_dst ; _ }) when
            (not (Macaddr.compare eth_dst client_macaddr = 0 ||
                  Macaddr.compare eth_dst c.Configuration.server_macaddr = 0 ||
                  Macaddr.compare eth_dst Macaddr.broadcast = 0)) ->
          (* not to server, client or broadcast.. *)
          Log.debug (fun f ->
              f "%d: forwarded to bridge for %s->%s" vnet_client_id
                (Macaddr.to_string eth_src) (Macaddr.to_string eth_dst));
          (* pass to virtual network *)
          begin
            Vnet.write vnet_switch t.vnet_client_id buf >|= function
            | Ok ()   -> ()
            | Error e ->
              Log.err (fun l -> l "Vnet write failed: %a" Mirage_device.pp_error e)
          end
        | Ok (Ethernet { dst = eth_dst ; src = eth_src ;
                         payload = Ipv4 { payload = Udp { dst = 67; _ }; _ };
                         _ })
        | Ok (Ethernet { dst = eth_dst ; src = eth_src ;
                         payload = Ipv4 { payload = Udp { dst = 68; _ }; _ };
                         _ }) ->
          Log.debug (fun f ->
              f "%d: dhcp %s->%s" vnet_client_id
                (Macaddr.to_string eth_src) (Macaddr.to_string eth_dst));
          Dhcp.callback dhcp buf
        | Ok (Ethernet { dst = eth_dst ; src = eth_src ;
                         payload = Arp { op = `Request }; _ }) ->
          Log.debug (fun f ->
              f "%d: arp %s->%s" vnet_client_id
                (Macaddr.to_string eth_src) (Macaddr.to_string eth_dst));
          (* Arp.input expects only the ARP packet, with no ethernet
             header prefix *)
          begin
            (* reply with global table if bridge is in use *)
            Lwt_mutex.with_lock global_arp_table.mutex (fun _ ->
                Global_arp.connect ~table:global_arp_table.table
                  global_arp_ethif
                |> Lwt.return)
          end
          >>= fun arp ->
          Global_arp.input arp (Cstruct.shift buf Ethif_wire.sizeof_ethernet)
        | Ok (Ethernet { payload = Ipv4 ({ dst; _ } as ipv4 ); _ }) ->
          (* For any new IP destination, create a stack to proxy for
            the remote system *)
          let localhost_ips =
            if Ipaddr.V4.(compare unspecified c.Configuration.host_ip) = 0
            then []
            else [ Ipaddr.V4 c.Configuration.host_ip ] in
          if dst = c.Configuration.gateway_ip then begin
            begin
              let open Lwt_result.Infix in
              find_endpoint dst >>= fun endpoint ->
              Log.debug (fun f ->
                  f "creating gateway TCP/IP proxy for %a" Ipaddr.V4.pp dst);
              (* The default Udp_nat instance doesn't work for us because
                 - in send_reply the address `localhost` is rewritten to the host address.
                   We need the gateway's address to be used.
                 - the remote port number is exposed to the container service;
                   we would like to use the listening port instead *)
              let udp_nat = Udp_nat.create ~preserve_remote_port:false clock in
              let send_reply =
                let open Lwt.Infix in
                function
                | { Hostnet_udp.dst = Ipaddr.V6 ipv6, _; _ } ->
                  Log.err (fun f -> f "Failed to write an IPv6 UDP datagram to: %a" Ipaddr.V6.pp ipv6);
                  Lwt.return_unit
                | { Hostnet_udp.src = _, src_port; dst = Ipaddr.V4 dst, dst_port; payload; _ } ->
                  begin find_endpoint c.Configuration.gateway_ip
                  >>= function
                  | Error (`Msg m) ->
                    Log.err (fun f -> f "%s" m);
                    Lwt.return_unit
                  | Ok endpoint ->
                    Stack_udp.write ~src_port ~dst ~dst_port endpoint.Endpoint.udp4 payload
                    >|= function
                    | Error e -> Log.err (fun f -> f "Failed to write an IPv4 packet: %a" Stack_udp.pp_error e)
                    | Ok () -> ()
                  end in
              Udp_nat.set_send_reply ~t:udp_nat ~send_reply;
              Gateway.create clock endpoint udp_nat [ c.Configuration.gateway_ip ]
                c.Configuration.host_names localhost_ips
            end >>= function
            | Error e ->
              Log.err (fun f ->
                  f "Failed to create a TCP/IP stack: %a" Switch.Port.pp_error e);
              Lwt.return_unit
            | Ok tcp_stack ->
              (* inject the ethernet frame into the new stack *)
              Gateway.input_ipv4 tcp_stack (Ipv4 ipv4) >|= function
              | Ok ()   -> ()
              | Error e ->
                Log.err (fun f -> f "failed to read TCP/IP input: %a" pp_error e);
          end else if dst = c.Configuration.host_ip && Ipaddr.V4.(compare unspecified c.Configuration.host_ip <> 0) then begin
            begin
              let open Lwt_result.Infix in
              find_endpoint dst >>= fun endpoint ->
              Log.debug (fun f ->
                  f "creating localhost TCP/IP proxy for %a" Ipaddr.V4.pp dst);
              Localhost.create clock endpoint udp_nat localhost_ips
            end >>= function
            | Error e ->
              Log.err (fun f ->
                  f "Failed to create a TCP/IP stack: %a" Switch.Port.pp_error e);
              Lwt.return_unit
            | Ok tcp_stack ->
              (* inject the ethernet frame into the new stack *)
              Localhost.input_ipv4 tcp_stack (Ipv4 ipv4) >|= function
              | Ok ()   -> ()
              | Error e ->
                Log.err (fun f -> f "failed to read TCP/IP input: %a" pp_error e);
          end else begin
            begin
              let open Lwt_result.Infix in
              find_endpoint dst >>= fun endpoint ->
              Log.debug (fun f ->
                  f "create remote TCP/IP proxy for %a" Ipaddr.V4.pp dst);
              Remote.create endpoint udp_nat icmp_nat
                c.Configuration.host_names localhost_ips
            end >>= function
            | Error e ->
              Log.err (fun f ->
                  f "Failed to create a TCP/IP stack: %a"
                    Switch.Port.pp_error e);
              Lwt.return_unit
            | Ok tcp_stack ->
              (* inject the ethernet frame into the new stack *)
              Remote.input_ipv4 tcp_stack (Ipv4 ipv4) >|= function
              | Ok ()   -> ()
              | Error e ->
                Log.err (fun l ->
                    l "error while reading remote IPv4 input: %a"
                      Stack_ipv4.pp_error e)
          end
        | _ ->
          Lwt.return_unit
      )
    >>= function
    | Error e ->
      Log.err (fun f -> f "TCP/IP not ready: %a" Switch.pp_error e);
      Lwt.fail_with "not ready"
    | Ok () ->
      Log.info (fun f -> f "TCP/IP ready");
      Lwt.return t

  let update_dns c clock =
    let config = match c.Configuration.resolver, c.Configuration.dns with
    | `Upstream, servers -> `Upstream servers
    | `Host, _ -> `Host
    in
    Log.info (fun f ->
        f "Updating resolvers to %s" (Hostnet_dns.Config.to_string config));
    !dns >>= Dns_forwarder.destroy >|= fun () ->
    Dns_policy.remove ~priority:3;
    Dns_policy.add ~priority:3 ~config;
    let local_ip = c.Configuration.gateway_ip in
    let local_address =
      { Dns_forward.Config.Address.ip = Ipaddr.V4 local_ip; port = 0 }
    in
    let builtin_names =
      (List.map (fun name -> name, Ipaddr.V4 c.Configuration.gateway_ip) c.Configuration.gateway_names)
      @ (List.map (fun name -> name, Ipaddr.V4 c.Configuration.host_ip) c.Configuration.host_names)
      (* FIXME: what to do if there are multiple VMs? *)
      @ (List.map (fun name -> name, Ipaddr.V4 c.Configuration.lowest_ip) c.Configuration.vm_names) in

    dns := dns_forwarder ~local_address ~builtin_names clock

  let update_dhcp c =
    Log.info (fun f ->
      f "Update DHCP configuration to %s"
        (match c.Configuration.dhcp_configuration with
         | None -> "None"
         | Some x -> Configuration.Dhcp_configuration.to_string x)
    );
    Hostnet_dhcp.update_global_configuration c.Configuration.dhcp_configuration;
    Lwt.return_unit

  let update_http c = match c.Configuration.http_intercept with
    | None ->
      Log.info (fun f -> f "Disabling transparent HTTP redirection");
      http := None;
      Lwt.return_unit
    | Some x ->
      Http_forwarder.of_json x
      >>= function
      | Error (`Msg m) ->
        Log.err (fun f -> f "Failed to decode transparent HTTP redirection json: %s" m);
        Lwt.return_unit
      | Ok t ->
        http := Some t;
        Log.info (fun f ->
          f "Updating transparent HTTP redirection: %s" (Http_forwarder.to_string t)
        );
        Lwt.return_unit

  let create_common clock vnet_switch c =
    (* If a `dns_path` is provided then watch it for updates *)
    let read_dns_file path =
      Log.info (fun f -> f "Reading DNS configuration from %s" path);
      Host.Files.read_file path
      >>= function
      | Error (`Msg m) ->
        Log.err (fun f -> f "Failed to read DNS configuration file %s: %s. Disabling current configuration." path m);
        update_dns { c with dns = Configuration.no_dns_servers } clock
      | Ok contents ->
        begin match Configuration.Parse.dns contents with
        | None ->
          Log.err (fun f -> f "Failed to parse DNS configuration file %s. Disabling current configuration." path);
          update_dns { c with dns = Configuration.no_dns_servers } clock
        | Some dns ->
          Log.info (fun f -> f "Updating DNS configuration to %s" (Dns_forward.Config.to_string dns));
          update_dns { c with dns } clock
        end in
    ( match c.dns_path with
      | None -> Lwt.return_unit
      | Some path ->
        begin match Host.Files.watch_file path
          (fun () ->
            Log.info (fun f -> f "DNS configuration file %s has changed" path);
            Lwt.async (fun () ->
              log_exception_continue "Parsing DNS configuration"
                (fun () ->
                  read_dns_file path
                )
            )
          ) with
        | Error (`Msg m) ->
          Log.err (fun f -> f "Failed to watch DNS configuration file %s for changes: %s" path m)
        | Ok _watch ->
          Log.info (fun f -> f "Watching DNS configuration file %s for changes" path)
        end;
        Lwt.return_unit
    ) >>= fun () ->

    let read_http_intercept_file path =
      Log.info (fun f -> f "Reading transparent HTTP redirection from %s" path);
      Host.Files.read_file path
      >>= function
      | Error (`Msg m) ->
        Log.err (fun f -> f "Failed to read transparent HTTP redirection from %s: %s. Disabling transparent HTTP redirection." path m);
        update_http { c with http_intercept = None }
      | Ok txt ->
        begin match Ezjsonm.from_string txt with
        | exception _ ->
          Log.err (fun f -> f "Failed to parse transparent HTTP redirection json: %s" txt);
          update_http { c with http_intercept = None }
        | http_intercept ->
          update_http { c with http_intercept = Some http_intercept }
        end in
    ( match c.http_intercept_path with
    | None -> Lwt.return_unit
    | Some path ->
      begin match Host.Files.watch_file path
        (fun () ->
          Log.info (fun f -> f "Transparent HTTP redirection configuration file %s has changed" path);
          Lwt.async (fun () ->
            log_exception_continue "Parsing transparent HTTP redirection configuration"
              (fun () ->
                read_http_intercept_file path
              )
          )
        ) with
      | Error (`Msg m) ->
        Log.err (fun f -> f "Failed to watch transparent HTTP redirection configuration file %s for changes: %s" path m)
      | Ok _watch ->
        Log.info (fun f -> f "Watching transparent HTTP redirection configuration file %s for changes" path)
      end;
      Lwt.return_unit
    ) >>= fun () ->

    Hostnet_dhcp.update_global_configuration c.Configuration.dhcp_configuration;
    let read_dhcp_json_file path =
      Log.info (fun f -> f "Reading DHCP configuration file from %s" path);
      Host.Files.read_file path
      >>= function
      | Error (`Msg m) ->
        Log.err (fun f -> f "Failed to read DHCP configuration from %s: %s. Disabling transparent HTTP redirection." path m);
        update_dhcp { c with dhcp_configuration = None }
      | Ok txt ->
        update_dhcp { c with dhcp_configuration = Configuration.Dhcp_configuration.of_string txt }
      in
    ( match c.dhcp_json_path with
    | None -> Lwt.return_unit
    | Some path ->
      begin match Host.Files.watch_file path
        (fun () ->
          Log.info (fun f -> f "DHCP configuration file %s has changed" path);
          Lwt.async (fun () ->
            log_exception_continue "Parsing DHCP configuration"
              (fun () ->
                read_dhcp_json_file path
              )
          )
        ) with
      | Error (`Msg m) ->
        Log.err (fun f -> f "Failed to watch DHCP configuration file %s for changes: %s" path m)
      | Ok _watch ->
        Log.info (fun f -> f "Watching DHCP configuration file %s for changes" path)
      end;
      Lwt.return_unit
    ) >>= fun () ->

    (* Set the static forwarding table before watching for changes on the dynamic table *)
    Gateway_forwards.set_static (c.Configuration.udpv4_forwards @ c.Configuration.tcpv4_forwards);
    let read_gateway_forwards_file path =
      Log.info (fun f -> f "Reading gateway forwards file from %s" path);
      Host.Files.read_file path
      >>= function
      | Error (`Msg "ENOENT") ->
        Log.info (fun f -> f "Not reading gateway forwards file %s becuase it does not exist" path);
        Lwt.return_unit
      | Error (`Msg m) ->
        Log.err (fun f -> f "Failed to read gateway forwards from %s: %s." path m);
        Gateway_forwards.update [];
        Lwt.return_unit
      | Ok txt ->
        match Gateway_forwards.of_string txt with
        | Ok xs ->
          Gateway_forwards.update xs;
          Lwt.return_unit
        | Error (`Msg m) ->
          Log.err (fun f -> f "Failed to parse gateway forwards from %s: %s." path m);
          Lwt.return_unit
      in
    ( match c.gateway_forwards_path with
    | None -> Lwt.return_unit
    | Some path ->
      begin match Host.Files.watch_file path
        (fun () ->
          Log.info (fun f -> f "Gateway forwards file %s has changed" path);
          Lwt.async (fun () ->
            log_exception_continue "Parsing gateway forwards"
              (fun () ->
                read_gateway_forwards_file path
              )
          )
        ) with
      | Error (`Msg "ENOENT") ->
        Log.info (fun f -> f "Not watching gateway forwards file %s because it does not exist" path)
      | Error (`Msg m) ->
        Log.err (fun f -> f "Failed to watch gateway forwards file %s for changes: %s" path m)
      | Ok _watch ->
        Log.info (fun f -> f "Watching gateway forwards file %s for changes" path)
      end;
      Lwt.return_unit
    ) >>= fun () ->

    Log.info (fun f -> f "Configuration %s" (Configuration.to_string c));
    let global_arp_table : arp_table = {
      mutex = Lwt_mutex.create();
      table =
        (c.Configuration.gateway_ip, c.Configuration.server_macaddr)
        :: (if Ipaddr.V4.(compare unspecified c.Configuration.host_ip) = 0 then []
            else [c.Configuration.host_ip,  c.Configuration.server_macaddr ]);
    } in
    let client_uuids : uuid_table = {
      mutex = Lwt_mutex.create();
      table = Hashtbl.create 50;
    } in
    let t = {
      configuration = c;
      global_arp_table;
      client_uuids;
      vnet_switch;
      clock;
    } in
    Lwt.return t

  let create_static clock vnet_switch c =
    update_http c
    >>= fun () ->
    update_dns c clock
    >>= fun () ->
    create_common clock vnet_switch c

  let connect_client_by_uuid_ip t (uuid:Uuidm.t) (preferred_ip:Ipaddr.V4.t option) =
    Lwt_mutex.with_lock t.client_uuids.mutex (fun () ->
        if (Hashtbl.mem t.client_uuids.table uuid) then begin
          (* uuid already used, get config *)
          let (ip, vnet_client_id) = (Hashtbl.find t.client_uuids.table uuid) in
          let mac = (Vnet.mac t.vnet_switch vnet_client_id) in
          Log.info (fun f->
              f "Reconnecting MAC %s with IP %s"
                (Macaddr.to_string mac) (Ipaddr.V4.to_string ip));
          match preferred_ip with
          | None -> Lwt_result.return mac
          | Some preferred_ip ->
            let old_ip,_ = Hashtbl.find t.client_uuids.table uuid in
            if (Ipaddr.V4.compare old_ip preferred_ip) != 0 then
              Lwt_result.fail (`Msg "UUID already assigned to a different IP than the IP requested by the client")
            else
              Lwt_result.return mac
        end else begin (* new uuid, register in bridge *)
          (* register new client on bridge *)
          Lwt.catch (fun () -> 
            let vnet_client_id = match Vnet.register t.vnet_switch with
            | `Ok x    -> Ok x
            | `Error e -> Error e
            in
            or_failwith "vnet_switch" @@ Lwt.return vnet_client_id
            >>= fun vnet_client_id ->
            let client_macaddr = (Vnet.mac t.vnet_switch vnet_client_id) in

            let used_ips =
              Hashtbl.fold (fun _ v l ->
                  let ip, _ = v in
                  l @ [ip]) t.client_uuids.table []
            in

            (* check if a specific IP is requested *)
            let preferred_ip =
              match preferred_ip with
              | None -> None
              | Some preferred_ip ->
                  Log.info (fun f ->
                      f "Client requested IP %s" (Ipaddr.V4.to_string preferred_ip));
                  let preferred_ip_int32 = Ipaddr.V4.to_int32 preferred_ip in
                  let highest_ip_int32 = Ipaddr.V4.to_int32 t.configuration.Configuration.highest_ip in
                  let lowest_ip_int32 = Ipaddr.V4.to_int32 t.configuration.Configuration.lowest_ip in
                  if (preferred_ip_int32 > highest_ip_int32)
                  || (preferred_ip_int32 <  lowest_ip_int32)
                  then begin
                    failwith "Preferred IP address out of range."
                  end;
                  if not (List.mem preferred_ip used_ips) then begin
                    Some preferred_ip
                  end else begin
                    Fmt.kstrf failwith "Preferred IP address %s already used."
                      (Ipaddr.V4.to_string preferred_ip)
                  end
            in

            (* look for a new unique IP *)
            let rec next_unique_ip next_ip =
              if (Ipaddr.V4.to_int32 next_ip) > (Ipaddr.V4.to_int32 t.configuration.Configuration.highest_ip)
              then begin
                failwith "No IP addresses available."
              end;
              if not (List.mem next_ip used_ips) then begin
                next_ip
              end else begin
                let next_ip =
                  Ipaddr.V4.of_int32 (Int32.succ (Ipaddr.V4.to_int32 next_ip))
                in
                next_unique_ip next_ip
              end
            in

            let client_ip = match preferred_ip with
            | None    -> next_unique_ip t.configuration.Configuration.lowest_ip
            | Some ip -> ip
            in

            (* Add IP to global ARP table *)
            Lwt_mutex.with_lock t.global_arp_table.mutex (fun () ->
                t.global_arp_table.table <- (client_ip, client_macaddr)
                                            :: t.global_arp_table.table;
                Lwt.return_unit)  >>= fun () ->

            (* add to client table and return mac *)
            Hashtbl.replace t.client_uuids.table uuid (client_ip, vnet_client_id);
            Lwt_result.return client_macaddr) (fun e -> 
                match e with
                | Failure msg -> Lwt_result.fail (`Msg msg)
                | e -> raise e) (* re-raise other exceptions *)
        end
      )

  let get_client_ip_id t uuid =
    Lwt_mutex.with_lock t.client_uuids.mutex (fun () ->
        Lwt.return (Hashtbl.find t.client_uuids.table uuid)
      )

  let connect t client =
    Log.debug (fun f -> f "accepted vmnet connection");
    begin
      Vmnet.of_fd
        ~connect_client_fn:(connect_client_by_uuid_ip t)
        ~server_macaddr:t.configuration.Configuration.server_macaddr
        ~mtu:t.configuration.Configuration.mtu client
      >>= function
      | Error (`Msg x) ->
        Lwt.fail_with ("rejected ethernet connection: " ^ x)
      | Ok x ->
        let client_macaddr = Vmnet.get_client_macaddr x in
        let client_uuid = Vmnet.get_client_uuid x in
        get_client_ip_id t client_uuid
        >>= fun (client_ip, vnet_client_id) ->
        connect x t.vnet_switch vnet_client_id
          client_macaddr { t.configuration with lowest_ip = client_ip }
          t.global_arp_table t.clock
    end

end

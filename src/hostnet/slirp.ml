open Lwt.Infix

let src =
  let src = Logs.Src.create "usernet" ~doc:"Mirage TCP/IP <-> socket proxy" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module IPMap = Map.Make(Ipaddr.V4)

let default_peer = "192.168.65.2"
let default_host = "192.168.65.1"
let default_highest_ip = Ipaddr.V4.of_string_exn "192.168.65.254"

(* random MAC from https://www.hellion.org.uk/cgi-bin/randmac.pl *)
let default_server_macaddr = Macaddr.of_string_exn "F6:16:36:BC:F9:C6"
let default_dns_extra = []
let default_uuid_preferred_ip_prefix = Bytes.make 12 '\000'

(* When forwarding TCP, the connection is proxied so the MTU/MSS is
   link-local.  When forwarding UDP, the datagram on the internal link
   is the same size as the corresponding datagram on the external
   link, so we have to be careful to respect the Do Not Fragment
   bit. *)
let safe_outgoing_mtu = 1452 (* packets above this size with DNF set
                                will get ICMP errors *)

(* The default MTU is limited by the maximum message size on a Hyper-V
   socket. On currently available windows versions, we need to stay
   below 8192 bytes *)
let default_mtu = 1500 (* used for the virtual ethernet link *)

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

let restart_on_change name to_string values =
  Active_config.tl values
  >>= fun values ->
  let v = Active_config.hd values in
  Log.info (fun f ->
      f "%s changed to %s in the database: restarting" name (to_string v));
  exit 1

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

type ('a, 'b) config = {
  server_macaddr: Macaddr.t;
  peer_ip: Ipaddr.V4.t;
  local_ip: Ipaddr.V4.t;
  highest_ip: Ipaddr.V4.t;
  extra_dns_ip: Ipaddr.V4.t list;
  get_domain_search: unit -> string list;
  get_domain_name: unit -> string;
  global_arp_table: arp_table;
  client_uuids: uuid_table;
  vnet_switch: 'b;
  mtu: int;
  host_names: Dns.Name.t list;
  clock: 'a;
  port_max_idle_time: int;
}

module Make
    (Config: Active_config.S)
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

  module Filteredif = Filter.Make(Vmnet)
  module Netif = Capture.Make(Filteredif)
  module Recorder = (Netif: Sig.RECORDER with type t = Netif.t)
  module Switch = Mux.Make(Netif)
  module Dhcp = Dhcp.Make(Clock)(Switch)

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
  end

  module Dns_forwarder =
    Hostnet_dns.Make(Stack_ipv4)(Stack_udp)(Stack_tcp)(Host.Sockets)(Host.Dns)
      (Host.Time)(Clock)(Recorder)
  module Http_forwarder =
    Hostnet_http.Make(Stack_ipv4)(Stack_udp)(Stack_tcp)(Host.Sockets)(Host.Dns)

  module Udp_nat = Hostnet_udp.Make(Host.Sockets)(Clock)(Host.Time)
  module Icmp_nat = Hostnet_icmp.Make(Host.Sockets)(Clock)(Host.Time)
  
  let dns_forwarder ~local_address ~host_names clock =
    Dns_forwarder.create ~local_address ~host_names clock (Dns_policy.config ())

  (* Global variable containing the global DNS configuration *)
  let dns =
    let ip = Ipaddr.V4 (Ipaddr.V4.of_string_exn default_host) in
    let local_address = { Dns_forward.Config.Address.ip; port = 0 } in
    ref (
      Clock.connect () >>= fun clock ->
      dns_forwarder ~local_address ~host_names:[] clock
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

  let string_of_id id =
    let src = Stack_tcp_wire.src id in
    let src_port = Stack_tcp_wire.src_port id in
    let dst = Stack_tcp_wire.dst id in
    let dst_port = Stack_tcp_wire.dst_port id in
    Fmt.strf "TCP %a:%d > %a:%d"
      Ipaddr.V4.pp_hum dst dst_port
      Ipaddr.V4.pp_hum src src_port

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
        id: Stack_tcp_wire.t;
        mutable socket: Host.Sockets.Stream.Tcp.flow option;
        mutable last_active_time: float;
      }

      let to_string t =
        Printf.sprintf "%s socket = %s last_active_time = %.1f"
          (string_of_id t.id)
          (match t.socket with None -> "closed" | _ -> "open")
          (Unix.gettimeofday ())

      (* Global table of active flows *)
      let all : t Id.Map.t ref = ref Id.Map.empty

      let filesystem () =
        let flows = Id.Map.fold (fun _ t acc -> to_string t :: acc) !all [] in
        Vfs.File.ro_of_string (String.concat "\n" flows)

      let create id socket =
        let socket = Some socket in
        let last_active_time = Unix.gettimeofday () in
        let t = { id; socket; last_active_time } in
        all := Id.Map.add id t !all;
        t
      let remove id =
        all := Id.Map.remove id !all
      let touch id =
        if Id.Map.mem id !all
        then (Id.Map.find id !all).last_active_time <- Unix.gettimeofday ()
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
      mutable last_active_time: float;
      (* Tasks that will be signalled if the endpoint is destroyed *)
      mutable on_destroy:       unit Lwt.u Tcp.Id.Map.t;
    }
    (** A generic TCP/IP endpoint *)

    let touch t =
      t.last_active_time <- Unix.gettimeofday ()

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
      let last_active_time = Unix.gettimeofday () in
      let on_destroy = Tcp.Id.Map.empty in
      let tcp_stack =
        { recorder; netif; ethif; arp; ipv4; icmpv4; udp4; tcp4; pending;
          last_active_time; clock; on_destroy }
      in
      Lwt.return tcp_stack

    let destroy t =
      Tcp.Id.Map.iter (fun _ u -> Lwt.wakeup_later u ()) t.on_destroy;
      t.on_destroy <- Tcp.Id.Map.empty

    let intercept_tcp_syn t ~id ~syn on_syn_callback (buf: Cstruct.t) =
      if syn then begin
        if Tcp.Id.Set.mem id t.pending then begin
          (* This can happen if the `connect` blocks for a few seconds *)
          Log.debug (fun
                      f -> f "%s: connection in progress, ignoring duplicate \
                              SYN" (string_of_id id));
          Lwt.return_unit
        end else begin
          t.pending <- Tcp.Id.Set.add id t.pending;
          (* Add a task to the "on_destroy" list which will be signalled if
             the Endpoint is disconnected from the switch and we should close
             connections. *)
          let close, close_request = Lwt.task () in
          t.on_destroy <- Tcp.Id.Map.add id close_request t.on_destroy;
          Lwt.finalize
            (fun () ->
               on_syn_callback close
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

    let input_tcp t ~id ~syn (ip, port) (buf: Cstruct.t) =
      intercept_tcp_syn t ~id ~syn (fun close ->
          Host.Sockets.Stream.Tcp.connect (ip, port)
          >>= function
          | Error (`Msg m) ->
            Log.debug (fun f ->
                f "%a:%d: failed to connect, sending RST: %s"
                  Ipaddr.pp_hum ip port m);
            Lwt.return (fun _ -> None)
          | Ok socket ->
            let tcp = Tcp.Flow.create id socket in
            let listeners port =
              Log.debug (fun f ->
                  f "%a:%d handshake complete" Ipaddr.pp_hum ip port);
              let f flow =
                match tcp.Tcp.Flow.socket with
                | None ->
                  Log.err (fun f ->
                      f "%s callback called on closed socket"
                        (Tcp.Flow.to_string tcp));
                  Lwt.return_unit
                | Some socket ->
                  Lwt.finalize (fun () ->
                    Lwt.pick [
                      Lwt.map
                        (function Error e -> Error (`Proxy e) | Ok x -> Ok x)
                        (Proxy.proxy t.clock flow socket);
                      Lwt.map
                        (fun () -> Error `Close)
                        close
                    ]
                      >>= function
                      | Error (`Close) ->
                        Log.info (fun f ->
                          f "%s proxy closed due to switch port disconnection"
                            (Tcp.Flow.to_string tcp));
                        Lwt.return_unit
                      | Error (`Proxy e) ->
                        Log.debug (fun f ->
                            f "%s proxy failed with %a"
                              (Tcp.Flow.to_string tcp) Proxy.pp_error e);
                        Lwt.return_unit
                      | Ok (_l_stats, _r_stats) ->
                        Lwt.return_unit
                    ) (fun () ->
                      Log.debug (fun f ->
                          f "closing flow %s" (string_of_id tcp.Tcp.Flow.id));
                      tcp.Tcp.Flow.socket <- None;
                      t.on_destroy <- Tcp.Id.Map.remove id t.on_destroy;
                      Tcp.Flow.remove tcp.Tcp.Flow.id;
                      Host.Sockets.Stream.Tcp.close socket
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

  type t = {
    vnet_client_id: Vnet.id;
    after_disconnect: unit Lwt.t;
    interface: Netif.t;
    switch: Switch.t;
    mutable endpoints: Endpoint.t IPMap.t;
    endpoints_m: Lwt_mutex.t;
    udp_nat: Udp_nat.t;
    icmp_nat: Icmp_nat.t;
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

  module Local = struct
    type t = {
      clock: Clock.t;
      endpoint: Endpoint.t;
      udp_nat: Udp_nat.t;
      dns_ips: Ipaddr.V4.t list;
    }
    (** Represents the local machine including NTP and DNS servers *)

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
      Endpoint.intercept_tcp_syn t.endpoint ~id ~syn (fun close ->
          !dns >>= fun t ->
          Dns_forwarder.handle_tcp ~t ~close
        ) raw
      >|= ok

    (* UDP to port 123: localhost NTP *)
    | Ipv4 { src;
             payload = Udp { src = src_port; dst = 123;
                             payload = Payload payload; _ }; _ } ->
      let localhost = Ipaddr.V4.localhost in
      Log.debug (fun f ->
          f "UDP/123 request from port %d -- sending it to %a:%d" src_port
            Ipaddr.V4.pp_hum localhost 123);
      let datagram =
        { Hostnet_udp.src = Ipaddr.V4 src, src_port;
          dst = Ipaddr.V4 localhost, 123; payload }
      in
      Udp_nat.input ~t:t.udp_nat ~datagram ()
      >|= ok

    (* UDP to any other port: localhost *)
    | Ipv4 { src; dst; ihl; dnf; raw;
             payload = Udp { src = src_port; dst = dst_port; len;
                             payload = Payload payload; _ }; _ } ->
      let description =
        Fmt.strf "%a:%d -> %a:%d" Ipaddr.V4.pp_hum src src_port Ipaddr.V4.pp_hum
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
            dst = Ipaddr.(V4 V4.localhost), dst_port; payload }
        in
        Udp_nat.input ~t:t.udp_nat ~datagram ()
        >|= ok
      end

    (* TCP to local ports *)
    | Ipv4 { src; dst;
             payload = Tcp { src = src_port; dst = dst_port; syn; raw;
                             payload = Payload _; _ }; _ } ->
      let id =
        Stack_tcp_wire.v ~src_port:dst_port ~dst:src ~src:dst ~dst_port:src_port
      in
      Endpoint.input_tcp t.endpoint ~id ~syn
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

  module Remote = struct

    type t = {
      endpoint:        Endpoint.t;
      udp_nat:         Udp_nat.t;
      icmp_nat:        Icmp_nat.t;
    }
    (** Represents a remote system by proxying data to and from sockets *)

    (** Handle IPv4 datagrams by proxying them to a remote system *)
    let input_ipv4 t ipv4 = match ipv4 with

    (* Respond to ICMP *)
    | Ipv4 { src; dst; payload = Icmp { ty; code; seq; id; payload = Payload p; _ }; _ } ->
      let datagram = {
        Hostnet_icmp.src = src; dst = dst;
        ty; code; seq; id; payload = p
      } in
      Icmp_nat.input ~t:t.icmp_nat ~datagram ()
      >|= ok

    (* Transparent HTTP intercept? *)
    | Ipv4 { src = dest_ip ; dst = local_ip;
             payload = Tcp { src = dest_port;
                             dst = local_port; syn; raw; _ }; _ } ->
      let id =
        Stack_tcp_wire.v
          ~src_port:local_port ~dst:dest_ip ~src:local_ip ~dst_port:dest_port
      in
      let callback = match !http with
      | None -> None
      | Some http -> Http_forwarder.handle ~dst:(local_ip, local_port) ~t:http
      in
      begin match callback with
      | None ->
        Endpoint.input_tcp t.endpoint ~id ~syn (Ipaddr.V4 local_ip, local_port)
          raw (* common case *)
        >|= ok
      | Some cb ->
        Endpoint.intercept_tcp_syn t.endpoint ~id ~syn (fun _ -> cb) raw
        >|= ok
      end
    | Ipv4 { src; dst; ihl; dnf; raw;
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
            dst = Ipaddr.V4 dst, dst_port; payload }
        in
        Udp_nat.input ~t:t.udp_nat ~datagram ()
        >|= ok
      end

    | _ -> Lwt_result.return ()

    let create endpoint udp_nat icmp_nat =
      let tcp_stack = { endpoint; udp_nat; icmp_nat } in
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
             Fmt.strf "%a last_active_time = %.1f"
               Ipaddr.V4.pp_hum ip t.Endpoint.last_active_time
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
    let get_nat_table_size t = Udp_nat.get_nat_table_size t.udp_nat

    let update_dns
        ?(local_ip = Ipaddr.V4 Ipaddr.V4.localhost) ?(host_names = []) clock
      =
      let local_address =
        { Dns_forward.Config.Address.ip = local_ip; port = 0 }
      in
      dns := dns_forwarder ~local_address ~host_names clock

    let update_http ?http:http_config ?https ?exclude () =
      Http_forwarder.create ?http:http_config ?https ?exclude ()
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
      Lwt_mutex.with_lock t.endpoints_m
        (fun () ->
          let now = Unix.gettimeofday () in
          let old_ips = IPMap.fold (fun ip endpoint acc ->
              let age = now -. endpoint.Endpoint.last_active_time in
              if age > (float_of_int port_max_idle_time) then (ip, endpoint) :: acc else acc
            ) t.endpoints [] in
          List.iter (fun (ip, endpoint) ->
              Switch.remove t.switch ip;
              Endpoint.destroy endpoint;
              t.endpoints <- IPMap.remove ip t.endpoints
            ) old_ips;
          Lwt.return_unit
        )
      >>= fun () ->
      delete_unused_endpoints t ~port_max_idle_time ()
    end

  let connect x vnet_switch vnet_client_id client_macaddr server_macaddr peer_ip
      local_ip highest_ip extra_dns_ip mtu get_domain_search get_domain_name
      (global_arp_table:arp_table) clock port_max_idle_time
    =

    let valid_subnets = [ Ipaddr.V4.Prefix.global ] in
    let valid_sources = [ Ipaddr.V4.of_string_exn "0.0.0.0" ] in

    Filteredif.connect ~valid_subnets ~valid_sources x
    |> fun (filteredif: Filteredif.t) ->
    Netif.connect filteredif
    |> fun interface ->
    Dns_forwarder.set_recorder interface;

    let kib = 1024 in
    (* Capture 256 KiB of DNS traffic *)
    Netif.add_match ~t:interface ~name:"dns.pcap" ~limit:(256 * kib)
      ~snaplen:1500 ~predicate:is_dns;
    (* Capture 64KiB of NTP traffic *)
    Netif.add_match ~t:interface ~name:"ntp.pcap" ~limit:(64 * kib)
      ~snaplen:1500 ~predicate:is_ntp;
    (* Capture 8KiB of ICMP traffic *)
    Netif.add_match ~t:interface ~name:"icmp.pcap" ~limit:(8 * kib)
      ~snaplen:1500 ~predicate:is_icmp;
    or_failwith "Switch.connect" (Switch.connect interface)
    >>= fun switch ->

    (* Serve a static ARP table *)
    let local_arp_table = [
      peer_ip, client_macaddr;
      local_ip, server_macaddr;
    ] @ (List.map (fun ip -> ip, server_macaddr) extra_dns_ip) in
    Global_arp_ethif.connect switch
    >>= fun global_arp_ethif ->

    (* Listen on local IPs *)
    let local_ips = local_ip :: extra_dns_ip in

    let highest_peer_ip = Some highest_ip in
    let dhcp = Dhcp.make ~server_macaddr ~peer_ip ~highest_peer_ip ~local_ip
        ~extra_dns_ip ~get_domain_search ~get_domain_name clock switch in

    let endpoints = IPMap.empty in
    let endpoints_m = Lwt_mutex.create () in
    let udp_nat = Udp_nat.create clock in
    let icmp_nat = Icmp_nat.create clock in
    let t = {
      vnet_client_id;
      after_disconnect = Vmnet.after_disconnect x;
      interface;
      switch;
      endpoints;
      endpoints_m;
      udp_nat;
      icmp_nat;
    } in
    Lwt.async @@ delete_unused_endpoints ~port_max_idle_time t;

    let find_endpoint ip =
      Lwt_mutex.with_lock t.endpoints_m
        (fun () ->
           if IPMap.mem ip t.endpoints
           then Lwt.return (Ok (IPMap.find ip t.endpoints))
           else begin
             Endpoint.create interface switch local_arp_table ip mtu clock
             >|= fun endpoint ->
             t.endpoints <- IPMap.add ip endpoint t.endpoints;
             Ok endpoint
           end
        ) in

    (* Send a UDP datagram *)
    let send_reply = function
    | { Hostnet_udp.src = Ipaddr.V4 src, src_port;
        dst = Ipaddr.V4 dst, dst_port; payload } ->
      (* [2] If the source address is localhost on the Mac, rewrite it to the
         virtual IP. This is the inverse of the rewrite above[1] *)
      let src =
        if Ipaddr.V4.compare src Ipaddr.V4.localhost = 0
        then local_ip
        else src in
      begin
        find_endpoint src >>= function
        | Error (`Msg m) ->
          Log.err (fun f ->
              f "Failed to create an endpoint for %a: %s" Ipaddr.V4.pp_hum dst m);
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
            Ipaddr.pp_hum src src_port Ipaddr.pp_hum dst dst_port);
      Lwt.return_unit in

    Udp_nat.set_send_reply ~t:udp_nat ~send_reply;

    (* Send an ICMP datagram *)
    let send_reply ~src ~dst ~payload =
      find_endpoint src >>= function
      | Error (`Msg m) ->
          Log.err (fun f ->
              f "Failed to create an endpoint for %a: %s" Ipaddr.V4.pp_hum dst m);
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

    Icmp_nat.set_send_reply ~t:icmp_nat ~send_reply;

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
          (Macaddr.to_string client_macaddr) (Macaddr.to_string server_macaddr));
    Switch.listen switch (fun buf ->
        let open Frame in
        match parse [ buf ] with
        | Ok (Ethernet { src = eth_src ; dst = eth_dst ; _ }) when
            (not (Macaddr.compare eth_dst client_macaddr = 0 ||
                  Macaddr.compare eth_dst server_macaddr = 0 ||
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
          if List.mem dst local_ips then begin
            begin
              let open Lwt_result.Infix in
              find_endpoint dst >>= fun endpoint ->
              Log.debug (fun f ->
                  f "creating local TCP/IP proxy for %a" Ipaddr.V4.pp_hum dst);
              Local.create clock endpoint udp_nat local_ips
            end >>= function
            | Error e ->
              Log.err (fun f ->
                  f "Failed to create a TCP/IP stack: %a" Switch.Port.pp_error e);
              Lwt.return_unit
            | Ok tcp_stack ->
              (* inject the ethernet frame into the new stack *)
              Local.input_ipv4 tcp_stack (Ipv4 ipv4) >|= function
              | Ok ()   -> ()
              | Error e ->
                Log.err (fun f -> f "failed to read TCP/IP input: %a" pp_error e);
          end else begin
            begin
              let open Lwt_result.Infix in
              find_endpoint dst >>= fun endpoint ->
              Log.debug (fun f ->
                  f "create remote TCP/IP proxy for %a" Ipaddr.V4.pp_hum dst);
              Remote.create endpoint udp_nat icmp_nat
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

  let create ?(host_names = [ Dns.Name.of_string "vpnkit.host" ]) clock vnet_switch config =
    let driver = [ "com.docker.driver.amd64-linux" ] in

    let max_connections_path = driver @ [ "slirp"; "max-connections" ] in
    Config.string_option config max_connections_path
    >>= fun string_max_connections ->
    let parse_max = function
    | None -> Lwt.return None
    | Some x -> Lwt.return (
        try Some (int_of_string @@ String.trim x)
        with _ ->
          Log.err (fun f ->
              f "Failed to parse slirp/max-connections value: '%s'" x);
          None
      ) in
    Active_config.map parse_max string_max_connections
    >>= fun max_connections ->
    let rec monitor_max_connections_settings settings =
      begin match Active_config.hd settings with
      | None ->
        Log.info (fun f -> f "remove connection limit");
        Host.Sockets.set_max_connections None
      | Some limit ->
        Log.info (fun f -> f "updating connection limit to %d" limit);
        Host.Sockets.set_max_connections (Some limit)
      end;
      Active_config.tl settings
      >>= fun settings ->
      monitor_max_connections_settings settings
    in
    Lwt.async (fun () ->
        log_exception_continue "monitor max connections settings" (fun () ->
            monitor_max_connections_settings max_connections));

    (* TODO Don't hardcode this *)
    let server_macaddr = default_server_macaddr in

    (* Watch for DNS server overrides *)
    let domain_search = ref [] in
    let get_domain_search () = !domain_search in
    let dns_path = driver @ [ "slirp"; "dns" ] in
    Config.string_option config dns_path
    >>= fun string_dns_settings ->
    Active_config.map
      (function
      | Some txt ->
        let open Dns_forward in
        begin match Config.of_string txt with
        | Ok config ->
          domain_search := config.Config.search;
          Lwt.return (Some config)
        | Error (`Msg m) ->
          Log.err (fun f ->
              f "failed to parse %s: %s" (String.concat "/" dns_path) m);
          Lwt.return None
        end
      | None ->
        Lwt.return None
      ) string_dns_settings
    >>= fun dns_settings ->
    let resolver_path = driver @ [ "slirp"; "resolver" ] in
    Config.string_option config resolver_path
    >>= fun string_resolver_settings ->
    Active_config.map
      (function
      | Some "host" -> Lwt.return `Host
      | _ -> Lwt.return `Upstream
      ) string_resolver_settings
    >>= fun resolver_settings ->

    let domain_name = ref "localdomain" in
    let get_domain_name () = !domain_name in
    let domain_name_path = driver @ [ "slirp"; "domain" ] in
    Config.string config ~default:(!domain_name) domain_name_path
    >>= fun domain_name_settings ->
    Lwt.async
      (fun () ->
         Active_config.iter
           (fun x ->
              domain_name := x;
              Lwt.return_unit
           ) domain_name_settings
      );

    let bind_path = driver @ [ "allowed-bind-address" ] in
    Config.string_option config bind_path
    >>= fun string_allowed_bind_address ->
    let parse_bind_address = function
    | None -> Lwt.return None
    | Some x ->
      let strings = List.map String.trim @@ Stringext.split x ~on:',' in
      let ip_opts = List.map
          (fun x ->
             try
               if x = ""
               then None
               else Some (Ipaddr.of_string_exn x)
             with _ ->
               Log.err (fun f ->
                   f "Failed to parse IP address in allowed-bind-address: %s" x);
               None
          ) strings in
      let ips =
        List.fold_left (fun acc x -> match x with
          | None   -> acc
          | Some x -> x :: acc
          ) [] ip_opts
      in
      Lwt.return (Some ips)
    in
    Active_config.map parse_bind_address string_allowed_bind_address
    >>= fun allowed_bind_address ->

    let rec monitor_allowed_bind_settings allowed_bind_address =
      Forward.set_allowed_addresses (Active_config.hd allowed_bind_address);
      Active_config.tl allowed_bind_address
      >>= fun allowed_bind_address ->
      monitor_allowed_bind_settings allowed_bind_address in
    Lwt.async (fun () ->
        log_exception_continue "monitor_allowed_bind_settings" (fun () ->
            monitor_allowed_bind_settings allowed_bind_address));

    let peer_ips_path = driver @ [ "slirp"; "docker" ] in
    let parse_ipv4 default x = match Ipaddr.V4.of_string @@ String.trim x with
    | None ->
      Log.err (fun f ->
          f "Failed to parse IPv4 address '%s', using default of %a"
            x Ipaddr.V4.pp_hum default);
      Lwt.return default
    | Some x -> Lwt.return x in
    let parse_ipv4_list default x =
      let all =
        List.map Ipaddr.V4.of_string @@
        List.filter (fun x -> x <> "") @@
        List.map String.trim @@
        Astring.String.cuts ~sep:"," x
      in
      let any_none, some = List.fold_left (fun (any_none, some) x -> match x with
        | None -> true, some
        | Some x -> any_none, x :: some
        ) (false, []) all in
      if any_none then begin
        Log.err (fun f ->
            f "Failed to parse IPv4 address list '%s', using default of %s" x
              (String.concat "," (List.map Ipaddr.V4.to_string default)));
        Lwt.return default
      end else Lwt.return some
    in

    Config.string config ~default:default_peer peer_ips_path
    >>= fun string_peer_ips ->
    Active_config.map (parse_ipv4 (Ipaddr.V4.of_string_exn default_peer))
      string_peer_ips
    >>= fun peer_ips ->
    Lwt.async (fun () ->
        restart_on_change "slirp/docker" Ipaddr.V4.to_string peer_ips);

    let host_ips_path = driver @ [ "slirp"; "host" ] in
    Config.string config ~default:default_host host_ips_path
    >>= fun string_host_ips ->
    Active_config.map (parse_ipv4 (Ipaddr.V4.of_string_exn default_host))
      string_host_ips
    >>= fun host_ips ->
    Lwt.async (fun () ->
        restart_on_change "slirp/host" Ipaddr.V4.to_string host_ips);

    let highest_ips_path = driver @ [ "slirp"; "highest-ip" ] in
    Config.string config ~default:"" highest_ips_path
    >>= fun string_highest_ips ->
    Active_config.map (parse_ipv4 default_highest_ip) string_highest_ips
    >>= fun highest_ips ->
    Lwt.async (fun () ->
        restart_on_change "slirp/highest-ips" Ipaddr.V4.to_string highest_ips);

    let extra_dns_ips_path = driver @ [ "slirp"; "extra_dns" ] in
    Config.string config ~default:(String.concat "," default_dns_extra)
      extra_dns_ips_path
    >>= fun string_extra_dns_ips ->
    Active_config.map
      (parse_ipv4_list (List.map Ipaddr.V4.of_string_exn default_dns_extra))
      string_extra_dns_ips
    >>= fun extra_dns_ips ->
    Lwt.async (fun () ->
        restart_on_change "slirp/extra_dns" (fun x ->
            String.concat "," (List.map Ipaddr.V4.to_string x)) extra_dns_ips);

    let peer_ip = Active_config.hd peer_ips in
    let local_ip = Active_config.hd host_ips in
    let highest_ip = Active_config.hd highest_ips in
    let extra_dns_ip = Active_config.hd extra_dns_ips in

    let upstream_servers =
      ref Dns_forward.Config.({servers = Server.Set.empty; search = [];
                               assume_offline_after_drops = None })
    in
    let resolver = ref `Upstream in
    let update_dns () =
      let config = match !resolver, !upstream_servers with
      | `Upstream, servers -> `Upstream servers
      | `Host, _ -> `Host
      in
      Log.info (fun f ->
          f "updating resolvers to %s" (Hostnet_dns.Config.to_string config));
      !dns >>= Dns_forwarder.destroy >|= fun () ->
      Dns_policy.remove ~priority:3;
      Dns_policy.add ~priority:3 ~config;
      let local_address =
        { Dns_forward.Config.Address.ip = Ipaddr.V4 local_ip; port = 0 }
      in
      dns := dns_forwarder ~local_address ~host_names clock
    in

    let rec monitor_dns_settings settings =
      begin match Active_config.hd settings with
      | None ->
        upstream_servers :=
          Dns_forward.Config.({ servers = Server.Set.empty;
                                search = [];
                                assume_offline_after_drops = None });
      | Some (servers: Dns_forward.Config.t) ->
        upstream_servers := servers;
      end;
      update_dns ()
      >>= fun () ->
      Active_config.tl settings
      >>= fun settings ->
      monitor_dns_settings settings
    in
    Lwt.async (fun () ->
        log_exception_continue "monitor upstream server DNS settings" (fun () ->
            monitor_dns_settings dns_settings));

    let rec monitor_resolver_settings settings =
      resolver := Active_config.hd settings;
      update_dns ()
      >>= fun () ->
      Active_config.tl settings
      >>= fun settings ->
      monitor_resolver_settings settings
    in
    Lwt.async (fun () ->
        log_exception_continue "monitor upstream DNS resolver settings" (fun () ->
            monitor_resolver_settings resolver_settings));

    let mtu_path = driver @ [ "slirp"; "mtu" ] in
    Config.int config ~default:default_mtu mtu_path
    >>= fun mtus ->
    Lwt.async (fun () -> restart_on_change "slirp/mtu" string_of_int mtus);
    let mtu = Active_config.hd mtus in

    let http_intercept_path = driver @ [ "slirp"; "http-intercept" ] in
    Config.string_option config http_intercept_path
    >>= fun string_http_intercept_settings ->
    let parse_http_intercept = function
    | None -> Lwt.return None
    | Some txt ->
      match Ezjsonm.from_string txt with
      | exception _ ->
        Log.err (fun f -> f "Failed to parse http-intercept json: %s" txt);
        Lwt.return None
      | j ->
        Http_forwarder.of_json j
        >>= function
        | Error (`Msg m) ->
          Log.err (fun f -> f "Failed to decode http-intercept json: %s" m);
          Lwt.return None
        | Ok t ->
          Lwt.return (Some t)
    in
    Active_config.map parse_http_intercept string_http_intercept_settings
    >>= fun http_intercept_settings ->
    let rec monitor_http_intercept_settings settings =
      http := Active_config.hd settings;
      ( match !http with
      | None -> Log.info (fun f -> f "Disabling transparent HTTP redirection")
      | Some x -> Log.info (fun f ->
          f "Enabling transparent HTTP redirection to %s"
            (Http_forwarder.to_string x)) );
      Active_config.tl settings
      >>= fun settings ->
      monitor_http_intercept_settings settings
    in
    Lwt.async (fun () ->
        log_exception_continue "monitor http interception settings" (fun () ->
            monitor_http_intercept_settings http_intercept_settings));

    let port_max_idle_time_path = driver @ [ "slirp"; "port-max-idle-time" ] in
    Config.int config ~default:300 port_max_idle_time_path
    >>= fun port_max_idle_times ->
    let port_max_idle_time = Active_config.hd port_max_idle_times in

    Log.info (fun f ->
        f "Creating slirp server peer_ip:%s local_ip:%s domain_search:%s \
           mtu:%d port_max_idle_time:%d"
          (Ipaddr.V4.to_string peer_ip) (Ipaddr.V4.to_string local_ip)
          (String.concat " " !domain_search) mtu port_max_idle_time
      );

    let global_arp_table : arp_table = {
      mutex = Lwt_mutex.create();
      table = [(local_ip, server_macaddr)];
    } in
    let client_uuids : uuid_table = {
      mutex = Lwt_mutex.create();
      table = Hashtbl.create 50;
    } in
    let t = {
      server_macaddr;
      peer_ip;
      local_ip;
      highest_ip;
      extra_dns_ip;
      get_domain_search;
      get_domain_name;
      global_arp_table;
      client_uuids;
      vnet_switch;
      mtu;
      host_names;
      clock;
      port_max_idle_time;
    } in
    Lwt.return t

  let client_connect_by_uuid t (uuid:Uuidm.t) =
    Lwt_mutex.with_lock t.client_uuids.mutex (fun () ->
        if (Hashtbl.mem t.client_uuids.table uuid) then begin
          (* uuid already used, get config *)
          let (ip, vnet_client_id) = (Hashtbl.find t.client_uuids.table uuid) in
          let mac = (Vnet.mac t.vnet_switch vnet_client_id) in
          Log.info (fun f->
              f "Reconnecting MAC %s with IP %s"
                (Macaddr.to_string mac) (Ipaddr.V4.to_string ip));
          Lwt.return mac (* may raise Not_found if id is unknown to the bridge *)
        end else begin (* new uuid, register in bridge *)
          (* register new client on bridge *)
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
            let uuid_bytes = Uuidm.to_bytes uuid in
            let uuid_prefix =
              Bytes.sub uuid_bytes 0 (Bytes.length default_uuid_preferred_ip_prefix)
            in
            if (Bytes.compare uuid_prefix default_uuid_preferred_ip_prefix) = 0
            then begin
              let uuid_suffix = Bytes.sub uuid_bytes 12 4 in
              let preferred_ip = Ipaddr.V4.of_bytes_exn uuid_suffix in
              Log.info (fun f ->
                  f "Client requested IP %s" (Ipaddr.V4.to_string preferred_ip));
              let preferred_ip_int32 = Ipaddr.V4.to_int32 preferred_ip in
              let highest_ip_int32 = Ipaddr.V4.to_int32 t.highest_ip in
              let lowest_ip_int32 = Ipaddr.V4.to_int32 t.peer_ip in
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
            end else begin
              None
            end
          in

          (* look for a new unique IP *)
          let rec next_unique_ip next_ip =
            if (Ipaddr.V4.to_int32 next_ip) > (Ipaddr.V4.to_int32 t.highest_ip)
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
          | None    -> next_unique_ip t.peer_ip
          | Some ip -> ip
          in

          (* Add IP to global ARP table *)
          Lwt_mutex.with_lock t.global_arp_table.mutex (fun () ->
              t.global_arp_table.table <- (client_ip, client_macaddr)
                                          :: t.global_arp_table.table;
              Lwt.return_unit)  >>= fun () ->

          (* add to client table and return mac *)
          Hashtbl.replace t.client_uuids.table uuid (client_ip, vnet_client_id);
          Lwt.return client_macaddr
        end
      )

  let get_client_ip_id t uuid =
    Lwt_mutex.with_lock t.client_uuids.mutex (fun () ->
        Lwt.return (Hashtbl.find t.client_uuids.table uuid)
      )

  let connect t client =
    Log.debug (fun f -> f "accepted vmnet connection");
    begin
      or_failwith "vmnet" @@
      Vmnet.of_fd
        ~client_macaddr_of_uuid:(client_connect_by_uuid t)
        ~server_macaddr:t.server_macaddr ~mtu:t.mtu client
      >>= fun x ->
      let client_macaddr = Vmnet.get_client_macaddr x in
      let client_uuid = Vmnet.get_client_uuid x in
      get_client_ip_id t client_uuid
      >>= fun (client_ip, vnet_client_id) ->
      connect x t.vnet_switch vnet_client_id client_macaddr t.server_macaddr
        client_ip t.local_ip t.highest_ip t.extra_dns_ip t.mtu
        t.get_domain_search t.get_domain_name t.global_arp_table
        t.clock t.port_max_idle_time
    end

end

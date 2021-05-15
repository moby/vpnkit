open Lwt.Infix
open Slirp_stack

let src =
  let src = Logs.Src.create "dns" ~doc:"Test the DNS forwarder" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let pp_ips = Fmt.(list ~sep:(unit ", ") Ipaddr.pp)
let pp_ip4s = Fmt.(list ~sep:(unit ", ") Ipaddr.V4.pp)

let run_test ?(timeout=Duration.of_sec 60) t =
  let timeout =
    Host.Time.sleep_ns timeout >>= fun () ->
    Lwt.fail_with "timeout"
  in
  Host.Main.run @@ Lwt.pick [ timeout; t ]

let run ?timeout ~pcap t = run_test ?timeout (with_stack ~pcap t)

let default_upstream_dns = Dns_policy.google_dns

let set_dns_policy ?builtin_names config =
  Dns_policy.remove ~priority:4;
  Dns_policy.add ~priority:4 ~config;
  Slirp_stack.Debug.update_dns ?builtin_names ()

let reset_dns_policy () =
  Dns_policy.clear ();
  Slirp_stack.Debug.update_dns ()

let test_dns_query server config () =
  let t _ stack =
    set_dns_policy config;
    let resolver = DNS.create stack.Client.t in
    DNS.gethostbyname ~server resolver "www.google.com" >|= function
    | (_ :: _) as ips ->
      Log.info (fun f -> f "www.google.com has IPs: %a" pp_ips ips);
    | _ ->
      Log.err (fun f -> f "Failed to lookup www.google.com");
      failwith "Failed to lookup www.google.com"
  in
  run ~pcap:"test_dns_query.pcap" t

let test_builtin_dns_query server config () =
  let name = "experimental.host.name.localhost" in
  let t _ stack =
    set_dns_policy ~builtin_names:[ Dns.Name.of_string name, Ipaddr.V4 (Ipaddr.V4.localhost) ] config;
    let resolver = DNS.create stack.Client.t in
    DNS.gethostbyname ~server resolver name >>= function
    | (_ :: _) as ips ->
      Log.info (fun f -> f "%s has IPs: %a" name pp_ips ips);
      Lwt.return ()
    | _ ->
      Log.err (fun f -> f "Failed to lookup %s" name);
      failwith ("Failed to lookup " ^ name)
  in
  run ~pcap:"test_builtin_dns_query.pcap" t

let test_etc_hosts_query server config () =
  let test_name = "vpnkit.is.cool.yes.really" in
  let t _ stack =
    set_dns_policy config;
    let resolver = DNS.create stack.Client.t in
    DNS.gethostbyname ~server resolver test_name >>= function
    | (_ :: _) as ips ->
      Log.err (fun f ->
          f "This test relies on the name %s not existing but it really \
             has IPs: %a" test_name pp_ips ips);
      Fmt.kstrf failwith "Test name %s really does exist" test_name
    | _ ->
      Hosts.etc_hosts := [
        test_name, Ipaddr.V4 (Ipaddr.V4.localhost);
      ];
      DNS.gethostbyname ~server resolver test_name >|= function
      | (_ :: _) as ips ->
        Log.info (fun f -> f "Name %s has IPs: %a" test_name pp_ips ips);
        Hosts.etc_hosts := []
      | _ ->
        Log.err (fun f -> f "Failed to lookup name from /etc/hosts");
        Hosts.etc_hosts := [];
        failwith "failed to lookup name from /etc/hosts"
  in
  run ~pcap:"test_etc_hosts_query.pcap" t

let test_etc_hosts_priority server config () =
  let name = "builtins.should.be.higher.priority" in
  let builtin_ip = Ipaddr.of_string_exn "127.0.0.1" in
  let hosts_ip = Ipaddr.of_string_exn "127.0.0.2" in
  let t _ stack =
    set_dns_policy ~builtin_names:[ Dns.Name.of_string name, builtin_ip ] config;
    Hosts.etc_hosts := [
      name, hosts_ip;
    ];
    let resolver = DNS.create stack.Client.t in
    DNS.gethostbyname ~server resolver name >>= function
    | [ ip ] ->
      Log.info (fun f -> f "%s has single IP: %a" name Ipaddr.pp ip);
      if Ipaddr.compare ip builtin_ip = 0
      then Lwt.return ()
      else failwith ("Builtin DNS names should have higher priority than /etc/hosts")
    | (_ :: _) as ips ->
      Log.info (fun f -> f "%s has IPs: %a" name pp_ips ips);
      failwith ("Duplicate DNS names resolved for " ^ name);
    | _ ->
      Log.err (fun f -> f "Failed to lookup %s" name);
      failwith ("Failed to lookup " ^ name)
  in
  run ~pcap:"test_etc_hosts_priority.pcap" t

let test_dns config =
  let prefix = Dns_policy.(Config.to_string @@ config ()) in [
    prefix ^ ": lookup ",
    ["", `Quick, test_dns_query primary_dns_ip config];

    prefix ^ ": builtins",
    [ "", `Quick, test_builtin_dns_query primary_dns_ip config ];

    prefix ^ ": _etc_hosts",
    [ "", `Quick, test_etc_hosts_query primary_dns_ip config ];

    prefix ^ ": _etc_hosts_priority",
    [ "", `Quick, test_etc_hosts_priority primary_dns_ip config ];
  ]

(* A real UDP server listening on a physical port *)
module Server = struct
  open Host.Sockets.Datagram
  type t = {
    ip: Ipaddr.t;
    port: int;
    server: Udp.server;
  }
  let with_server ip answers f =
    Udp.bind ~description:"DNS server" (ip, 0)
    >>= fun server ->
    Udp.listen server
      (fun flow ->
        Log.debug (fun f -> f "Received UDP datagram");
	      let open Dns.Packet in
        Udp.read flow
        >>= function
        | Error _ ->
          Log.err (fun f -> f "Udp.listen failed to read");
          Lwt.return_unit
        | Ok `Eof ->
          Log.err (fun f -> f "Udp.read got EOF");
          Lwt.return_unit
        | Ok (`Data buf) ->
          let len = Cstruct.len buf in
          begin match Dns.Protocol.Server.parse (Cstruct.sub buf 0 len) with
          | None ->
            Log.err (fun f -> f "failed to parse DNS packet");
            Lwt.return_unit
          | Some ({ questions = [ _question ]; _ } as request) ->

            let reply answers =
              let id = request.id in
              let detail =
                { request.detail with Dns.Packet.qr = Dns.Packet.Response; ra = true }
              in
              let questions = request.questions in
              let authorities = [] and additionals = [] in
              { Dns.Packet.id; detail; questions; answers; authorities; additionals }
            in
            let buf = marshal @@ reply answers in
            Log.info (fun f -> f "DNS response is a UDP datagram of length %d" (Cstruct.len buf));
            begin Udp.write flow buf
            >>= function
            | Ok () ->
              Lwt.return_unit
            | Error _ ->
              Log.err (fun f -> f "Failed to send UDP response");
              Lwt.return_unit
            end
          | Some _ ->
            Log.info (fun f -> f "Dropping unexpected DNS request");
            Lwt.return_unit
          end
      );
    let _, realport = Udp.getsockname server in
    let t = { ip; port = realport; server } in
    Lwt.finalize (fun () -> f t.port) (fun () -> Udp.shutdown t.server)
end

let err_udp e = Fmt.kstrf failwith "%a" Client.UDPV4.pp_error e

let udp_rpc client src_port dst dst_port buffer =
  let udpv4 = Client.udpv4 client.Client.t in
  let send_request () =
    Client.UDPV4.write ~src_port ~dst ~dst_port udpv4 buffer
    >>= function
    | Error e -> err_udp e
    | Ok ()   -> Lwt.return_unit in

  let response = ref None in
  Client.listen_udpv4 client.Client.t ~port:src_port (fun ~src:_ ~dst:_ ~src_port:remote_src_port buffer ->
    Log.debug (fun f ->
        f "Received UDP %d -> %d" remote_src_port src_port);
    begin match !response with
    | Some _ -> () (* drop duplicates *)
    | None -> response := Some buffer
    end;
    Lwt.return_unit
  );
  let rec loop () =
    send_request ()
    >>= fun () ->
    match !response with
    | Some x -> Lwt.return x
    | None ->
      Host.Time.sleep_ns (Duration.of_sec 1)
      >>= fun () ->
      loop () in
  loop ()

let query_a name =
  let open Dns.Packet in
  let id = Random.int 0xffff in
  let detail = { qr = Query; opcode = Standard; aa = false; tc = false; rd = true; ra = false; rcode = NoError } in
  let questions = [ { q_name = Dns.Name.of_string name; q_type = Q_A; q_class = Q_IN; q_unicast = Q_Normal }] in
  let answers = [] and authorities = [] and additionals = [] in
  { id; detail; questions; answers; authorities; additionals }

let truncate_big_response () =
  let t _ client =
    let ip = Ipaddr.V4 Ipaddr.V4.localhost in
    (* The DNS response will be over 512 bytes *)
    let answers = Array.to_list @@ Array.make 64
      { Dns.Packet.name = Dns.Name.of_string "anything"; cls = RR_IN;
        flush = false; ttl = 0l; rdata = A Ipaddr.V4.localhost } in
    Server.with_server ip answers
      (fun port ->
        let open Dns_forward.Config in
        let servers = Server.Set.of_list [
          { Server.address = { Address.ip; port };
            zones = Domain.Set.empty;
            timeout_ms = Some 2000; order = 0
          }
        ] in
        let config = `Upstream { servers; search = []; assume_offline_after_drops = None } in
        set_dns_policy config;
        Lwt.finalize
          (fun () ->
            udp_rpc client 1024 primary_dns_ip 53 (Dns.Packet.marshal @@ query_a "very.big.name")
            >>= fun response ->
            Log.err (fun f -> f "UDP response has length %d" (Cstruct.len response));
            begin match Dns.Protocol.Server.parse response with
            | None ->
              failwith "failed to parse truncated DNS response"
            | Some { Dns.Packet.detail = { tc = true; _ }; answers; _ } ->
              Log.info (fun f -> f "DNS response has truncated bit set");
              if List.length answers <> 29
              then failwith (Printf.sprintf "expected 29 answers, got %d" (List.length answers));
              Lwt.return_unit
            | Some { Dns.Packet.detail = { tc = false; _ }; _ } ->
              failwith "DNS response does not have truncated bit set"
            end
          ) (fun () -> reset_dns_policy (); Lwt.return_unit)
      )
      in
  run ~pcap:"truncate_big_response.pcap" t

let suite = test_dns `Host @ (test_dns default_upstream_dns) @ [
  "big UDP responses are truncated",
  [ "", `Quick, truncate_big_response ]
]

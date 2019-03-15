open Lwt.Infix
open Slirp_stack

let src =
  let src = Logs.Src.create "dns" ~doc:"Test the DNS forwarder" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let pp_ips = Fmt.(list ~sep:(unit ", ") Ipaddr.pp_hum)
let pp_ip4s = Fmt.(list ~sep:(unit ", ") Ipaddr.V4.pp_hum)

let run_test ?(timeout=Duration.of_sec 60) t =
  let timeout =
    Host.Time.sleep_ns timeout >>= fun () ->
    Lwt.fail_with "timeout"
  in
  Host.Main.run @@ Lwt.pick [ timeout; t ]

let run ?timeout ~pcap t = run_test ?timeout (with_stack ~pcap t)

let default_upstream_dns = Dns_policy.google_dns

let set_dns_policy ?builtin_names config =
  Mclock.connect () >|= fun clock ->
  Dns_policy.remove ~priority:3;
  Dns_policy.add ~priority:3 ~config;
  Slirp_stack.Debug.update_dns ?builtin_names clock

let test_dns_query server config () =
  let t _ stack =
    set_dns_policy config >>= fun () ->
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
    set_dns_policy ~builtin_names:[ Dns.Name.of_string name, Ipaddr.V4 (Ipaddr.V4.localhost) ] config
    >>= fun () ->
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
    set_dns_policy config >>= fun () ->
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
    set_dns_policy ~builtin_names:[ Dns.Name.of_string name, builtin_ip ] config
    >>= fun () ->
    Hosts.etc_hosts := [
      name, hosts_ip;
    ];
    let resolver = DNS.create stack.Client.t in
    DNS.gethostbyname ~server resolver name >>= function
    | [ ip ] ->
      Log.info (fun f -> f "%s has single IP: %a" name Ipaddr.pp_hum ip);
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

module Server = struct
  open Host.Sockets.Datagram
  type t = {
    ip: Ipaddr.t;
    port: int;
    server: Udp.server;
  }
  let with_server ip f =
    Udp.bind ~description:"DNS server" (ip, 0)
    >>= fun server ->
    Udp.listen server
      (fun _flow ->
        Log.debug (fun f -> f "Received UDP datagram");
        Lwt.return_unit
      );
    let _, realport = Udp.getsockname server in
    let t = { ip; port = realport; server } in
    Lwt.finalize (fun () -> f t.port) (fun () -> Udp.shutdown t.server)
end

let truncate_big_response () =
  let t _ _stack =
    let ip = Ipaddr.V4 Ipaddr.V4.localhost in
    Server.with_server ip
      (fun _port ->
      set_dns_policy default_upstream_dns
      >>= fun () ->
        Lwt.return_unit
      ) in
  run ~pcap:"truncate_big_response.pcap" t

let suite = test_dns `Host @ (test_dns default_upstream_dns) @ [
  "big UDP responses are truncated",
  [ "", `Quick, truncate_big_response ]
]

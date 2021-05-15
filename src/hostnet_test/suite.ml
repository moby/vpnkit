open Lwt.Infix
open Slirp_stack

let src =
  let src = Logs.Src.create "test" ~doc:"Test the slirp stack" in
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

let test_dhcp_query () =
  let t _ stack =
    let ips = Client.IPV4.get_ip (Client.ipv4 stack.Client.t) in
    Log.info (fun f -> f "Got an IP: %a" pp_ip4s ips);
    Lwt.return ()
  in
  run ~pcap:"test_dhcp_query.pcap" t

let test_max_connections () =
  let t _ stack =
    Lwt.finalize (fun () ->
        let resolver = DNS.create stack.Client.t in
        DNS.gethostbyname ~server:primary_dns_ip resolver "www.google.com"
        >>= function
        | Ipaddr.V4 ip :: _ ->
          Log.info (fun f -> f "Setting max connections to 0");
          Host.Sockets.set_max_connections (Some 0);
          begin
            Client.TCPV4.create_connection (Client.tcpv4 stack.Client.t) (ip, 80)
            >|= function
            | Ok _ ->
              Log.err (fun f ->
                  f "Connected to www.google.com, max_connections exceeded");
              failwith "too many connections"
            | Error _ ->
              Log.debug (fun f ->
                  f "Expected failure to connect to www.google.com")
          end
          >>= fun () ->
          Log.info (fun f -> f "Removing connection limit");
          Host.Sockets.set_max_connections None;
          (* Check that connections work again *)
          begin
            Client.TCPV4.create_connection (Client.tcpv4 stack.Client.t) (ip, 80)
            >|= function
            | Ok _ ->
              Log.debug (fun f -> f "Connected to www.google.com");
            | Error _ ->
              Log.debug (fun f ->
                  f "Failure to connect to www.google.com: removing \
                     max_connections limit didn't work");
              failwith "wrong max connections limit"
          end
        | _ ->
          Log.err (fun f ->
              f "Failed to look up an IPv4 address for www.google.com");
          failwith "http_fetch dns"
      ) (fun () ->
        Log.info (fun f -> f "Removing connection limit");
        Host.Sockets.set_max_connections None;
        Lwt.return_unit
      )
  in
  run ~timeout:(Duration.of_sec 240) ~pcap:"test_max_connections.pcap" t

let test_http_fetch () =
  let t _ stack =
    let resolver = DNS.create stack.Client.t in
    DNS.gethostbyname resolver "www.google.com" >>= function
    | Ipaddr.V4 ip :: _ ->
      begin
        Client.TCPV4.create_connection (Client.tcpv4 stack.Client.t) (ip, 80)
        >>= function
        | Error _ ->
          Log.err (fun f -> f "Failed to connect to www.google.com:80");
          failwith "http_fetch"
        | Ok flow ->
          Log.info (fun f -> f "Connected to www.google.com:80");
          let page = Io_page.(to_cstruct (get 1)) in
          let http_get = "GET / HTTP/1.0\nHost: anil.recoil.org\n\n" in
          Cstruct.blit_from_string http_get 0 page 0 (String.length http_get);
          let buf = Cstruct.sub page 0 (String.length http_get) in
          Client.TCPV4.write flow buf >>= function
          | Error `Closed ->
            Log.err (fun f ->
                f "EOF writing HTTP request to www.google.com:80");
            failwith "EOF on writing HTTP GET"
          | Error _ ->
            Log.err (fun f ->
                f "Failure writing HTTP request to www.google.com:80");
            failwith "Failure on writing HTTP GET"
          | Ok () ->
            let rec loop total_bytes =
              Client.TCPV4.read flow >>= function
              | Ok `Eof     -> Lwt.return total_bytes
              | Error _ ->
                Log.err (fun f ->
                    f "Failure read HTTP response from www.google.com:80");
                failwith "Failure on reading HTTP GET"
              | Ok (`Data buf) ->
                Log.info (fun f ->
                    f "Read %d bytes from www.google.com:80" (Cstruct.len buf));
                Log.info (fun f -> f "%s" (Cstruct.to_string buf));
                loop (total_bytes + (Cstruct.len buf))
            in
            loop 0 >|= fun total_bytes ->
            Log.info (fun f -> f "Response had %d total bytes" total_bytes);
            if total_bytes == 0 then failwith "response was empty"
      end
    | _ ->
      Log.err (fun f ->
          f "Failed to look up an IPv4 address for www.google.com");
      failwith "http_fetch dns"
  in
  run ~pcap:"test_http_fetch.pcap" t

module DevNullServer = struct
  (* Accept local TCP connections, throw away all incoming data and then return
     the total number of bytes processed. *)
  type t = {
    local_port: int;
    server: Host.Sockets.Stream.Tcp.server;
  }

  let accept flow =
    let module Channel = Mirage_channel.Make(Host.Sockets.Stream.Tcp) in
    let ch = Channel.create flow in
    (* XXX: this looks like it isn't tail recursive to me *)
    let rec drop_all_data count =
      Channel.read_some ch >>= function
      | Error e -> Fmt.kstrf Lwt.fail_with "%a" Channel.pp_error e
      | Ok `Eof -> Lwt.return count
      | Ok (`Data buffer) ->
        drop_all_data Int64.(add count (of_int (Cstruct.len buffer)))
    in
    drop_all_data 0L
    >>= fun total ->
    let response = Cstruct.create 8 in
    Cstruct.LE.set_uint64 response 0 total;
    Channel.write_buffer ch response;
    Channel.flush ch >>= function
    | Error e -> Fmt.kstrf Lwt.fail_with "%a" Channel.pp_write_error e
    | Ok ()   -> Lwt.return_unit

  let create () =
    Host.Sockets.Stream.Tcp.bind (Ipaddr.V4 Ipaddr.V4.localhost, 0)
    >|= fun server ->
    let _, local_port = Host.Sockets.Stream.Tcp.getsockname server in
    Host.Sockets.Stream.Tcp.listen server accept;
    { local_port; server }

  let to_string t = Printf.sprintf "tcp:127.0.0.1:%d" t.local_port
  let destroy t = Host.Sockets.Stream.Tcp.shutdown t.server
  let with_server f =
    create () >>= fun server ->
    Lwt.finalize (fun () -> f server) (fun () -> destroy server)
end

let rec count = function 0 -> [] | n -> () :: (count (n - 1))

let run' ?timeout ~pcap t =
  run ?timeout ~pcap (fun x b ->
      DevNullServer.with_server (fun { DevNullServer.local_port; _ } ->
          t local_port x b)
    )

let test_many_connections n () =
  let t local_port _ stack =
    (* Note that the stack will consume a small number of file
       descriptors itself and each loopback connection will consume
       2: one for client and one for server. *)
    (* Instead of counting calls to `connect` and trying to
       calculate overheads, we connect until the system tells us
       we've hit the target number of connections. *)
    let rec loop acc i =
      if Host.Sockets.get_num_connections () >= n
      then Lwt.return acc
      else
        Client.TCPV4.create_connection (Client.tcpv4 stack.Client.t)
          (Ipaddr.V4.localhost, local_port)
        >>= function
        | Ok c ->
          Log.info (fun f ->
              f "Connected %d, total tracked connections %d" i
                (Host.Sockets.get_num_connections ()));
          loop (c :: acc) (i + 1)
        | Error _ ->
          Fmt.kstrf failwith
            "Connection %d failed, total tracked connections %d" i
            (Host.Sockets.get_num_connections ())
    in
    loop [] 0 >|= fun flows ->
    Log.info (fun f ->
        f "Connected %d, total tracked connections %d"
          (List.length flows) (Host.Sockets.get_num_connections ()));
    (* How many connections is this? *)
  in
  run' ~timeout:(Duration.of_sec 240) ~pcap:"test_many_connections.pcap" t

let test_stream_data connections length () =
  let t local_port _ stack =
    Lwt_list.iter_p (fun () ->
        let rec connect () =
          Client.TCPV4.create_connection (Client.tcpv4 stack.Client.t)
            (Ipaddr.V4.localhost, local_port)
          >>= function
          | Error `Refused ->
            Log.info (fun f -> f "DevNullServer Refused connection");
            Host.Time.sleep_ns (Duration.of_ms 200)
            >>= fun () ->
            connect ()
          | Error `Timeout ->
            Log.err (fun f -> f "DevNullServer connection timeout");
            failwith "DevNullServer connection timeout";
          | Error e ->
            Log.err (fun f ->
                f "DevNullServer connnection failure: %a"
                  Client.TCPV4.pp_error e);
            Fmt.kstrf failwith "%a" Client.TCPV4.pp_error e
          | Ok flow ->
            Log.info (fun f -> f "Connected to local server");
            Lwt.return flow
        in
        connect ()
        >>= fun flow ->
        let page = Io_page.(to_cstruct (get 1)) in
        Cstruct.memset page 0;
        let rec loop remaining =
          if remaining = 0
          then Lwt.return ()
          else begin
            let this_time = min remaining (Cstruct.len page) in
            let buf = Cstruct.sub page 0 this_time in
            Client.TCPV4.write flow buf >>= function
            | Error `Closed ->
              Log.err (fun f ->
                  f "EOF writing to DevNullServerwith %d bytes left"
                    remaining);
              (* failwith "EOF on writing to DevNullServer" *)
              Lwt.return ()
            | Error _ ->
              Log.err (fun f ->
                  f "Failure writing to DevNullServer with %d bytes left"
                    remaining);
              (* failwith "Failure on writing to DevNullServer" *)
              Lwt.return ()
            | Ok () ->
              loop (remaining - this_time)
          end
        in
        loop length >>= fun () ->
        Client.TCPV4.close flow >>= fun () ->
        Client.TCPV4.read flow >|= function
        | Ok `Eof ->
          Log.err (fun f -> f "EOF reading result from DevNullServer");
          (* failwith "EOF reading result from DevNullServer" *)
        | Error _ ->
          Log.err (fun f -> f "Failure reading result from DevNullServer");
          (* failwith "Failure on reading result from DevNullServer" *)
        | Ok (`Data buf) ->
          Log.info (fun f ->
              f "Read %d bytes from DevNullServer" (Cstruct.len buf));
          let response = Cstruct.LE.get_uint64 buf 0 in
          if Int64.to_int response != length
          then Fmt.kstrf failwith
              "Response was %Ld while expected %d" response length;
      ) (count connections)
  in
  run' ~pcap:"test_stream_data.pcap" t

let test_dhcp = [
  "DHCP: simple query",
  ["check that the DHCP server works", `Quick, test_dhcp_query];
]

let test_tcp = [
  "HTTP GET", [ "HTTP GET http://www.google.com/", `Quick, test_http_fetch ];

  "Max connections",
  [ "HTTP GET fails beyond max connections", `Quick, test_max_connections ];

  "TCP streaming",
  [ "1 TCP connection transferring 1 KiB", `Quick, test_stream_data 1 1024 ];

  (*
  "10 TCP connections each transferring 1 KiB", `Quick, test_stream_data 10 1024;
  "32 TCP connections each transferring 1 KiB", `Quick, test_stream_data 32 1024;
  "1 TCP connection transferring 1 MiB", `Quick, test_stream_data 1 (1024*1024);
  "32 TCP connections each transferring 1 MiB", `Quick, test_stream_data 32
                                                        (1024*1024);
  "1 TCP connection transferring 1 GiB", `Slow, test_stream_data 1
                                                (1024*1024*1024);
  "32 TCP connections each transferring 1 GiB", `Slow, test_stream_data 32
                                                       (1024*1024*1024);
  *)
]

let tests =
  Hosts_test.tests @ Forwarding.tests @ test_dhcp
  @ Test_dns.suite
  @ test_tcp @ Test_nat.tests @ Test_http.tests @ Test_http.Exclude.tests
  @ Test_half_close.tests @ Test_ping.tests
  @ Test_bridge.tests @ Test_forward_protocol.suite

let scalability = [
  "1026conns",
  [ "Test many connections", `Quick, test_many_connections (1024 + 2) ];
  "nmap the host",
  [ "check that we can survive an agressive port scan", `Quick, Test_nmap.test_nmap ];
]

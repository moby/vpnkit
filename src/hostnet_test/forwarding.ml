open Lwt.Infix

let src =
  let src = Logs.Src.create "test" ~doc:"Test the forwarding code" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let (>>*=) m f = m >>= function
  | Ok x -> f x
  | Error (`Msg m) -> failwith m

let run ?(timeout=Duration.of_sec 60) t =
  let timeout =
    Host.Time.sleep_ns timeout >>= fun () ->
    Lwt.fail_with "timeout"
  in
  Host.Main.run @@ Lwt.pick [ timeout; t ]

module Channel = Mirage_channel.Make(Host.Sockets.Stream.Tcp)

module ForwardServer = struct
  (** Accept connections, read the forwarding header and run a proxy.
      This is a minimal "vpnkit-forwarder" *)

  module Mux = Forwarder.Multiplexer.Make(Host.Sockets.Stream.Tcp)

  module Proxy =
    Mirage_flow_combinators.Proxy
      (Mclock)(Mux.Channel)(Host.Sockets.Stream.Tcp)

  let accept flow =
    let forever, _u = Lwt.task () in
    let _mux = Mux.connect flow "ForwardServer"
      (fun client_flow destination ->
        let open Forwarder.Frame.Destination in
        Log.info (fun f -> f "ForwardServer.connect to %s" (to_string destination));
        match destination with
        | `Tcp(ip, port) -> begin
          Host.Sockets.Stream.Tcp.connect (ip, port) >>= function
          | Error (`Msg x) -> failwith x
          | Ok remote ->
            Lwt.finalize (fun () ->
                Proxy.proxy client_flow remote >>= function
                | Error e -> Fmt.kstrf failwith "%a" Proxy.pp_error e
                | Ok (_l_stats, _r_stats) -> Lwt.return ()
              ) (fun () ->
                Host.Sockets.Stream.Tcp.close remote
              )
        end
        | `Udp(ip, port) -> begin
          Host.Sockets.Datagram.Udp.connect (ip, port) >>= function
          | Error (`Msg x) -> failwith x
          | Ok remote ->
            let from_vsock_buffer = Cstruct.create (Constants.max_udp_length + Forwarder.Frame.Udp.max_sizeof) in
            (* A NAT table with one entry *)
            let from = ref None in
            let rec vsock2internet () =
              let read_into flow buf =
                Mux.Channel.read_into flow buf >>= function
                | Ok `Eof       -> Lwt.fail End_of_file
                | Error e       -> Fmt.kstrf Lwt.fail_with "%a" Mux.Channel.pp_error e
                | Ok (`Data ()) -> Lwt.return () in
              let read_next () =
                read_into client_flow (Cstruct.sub from_vsock_buffer 0 2) >>= fun () ->
                let frame_length = Cstruct.LE.get_uint16 from_vsock_buffer 0 in
                if frame_length > (Cstruct.len from_vsock_buffer) then begin
                  Log.err (fun f ->
                      f "UDP encapsulated frame length is %d but buffer has length %d: \
                        dropping" frame_length (Cstruct.len from_vsock_buffer));
                  Lwt.return None
                end else begin
                  let rest = Cstruct.sub from_vsock_buffer 2 (frame_length - 2) in
                  read_into client_flow rest >|= fun () ->
                  let udp, payload = Forwarder.Frame.Udp.read from_vsock_buffer in
                  Some (payload, (udp.Forwarder.Frame.Udp.ip, udp.Forwarder.Frame.Udp.port))
                end in
              read_next ()
              >>= function
              | None -> vsock2internet ()
              | Some (payload, (ip, port)) ->
                from := Some (ip, port);
                Host.Sockets.Datagram.Udp.write remote payload
                >>= function
                | Error _ -> Lwt.return_unit
                | Ok () ->
                  vsock2internet () in
            let write_header_buffer = Cstruct.create (Constants.max_udp_length + Forwarder.Frame.Udp.max_sizeof) in
            let rec internet2vsock () =
              let write flow buf =
                Mux.Channel.write flow buf >>= function
                | Error `Closed -> Lwt.fail End_of_file
                | Error e       -> Fmt.kstrf Lwt.fail_with "%a" Mux.Channel.pp_write_error e
                | Ok ()         -> Lwt.return () in
              Host.Sockets.Datagram.Udp.read remote
              >>= function
              | Ok `Eof -> Lwt.return_unit
              | Error _ -> Lwt.return_unit
              | Ok (`Data buf) ->
                begin match !from with
                | None ->
                  Log.info (fun f -> f "ForwardServer dropping datagram, no from address");
                  internet2vsock ()
                | Some (ip, port) ->
                  let udp = Forwarder.Frame.Udp.({
                      ip; port;
                      payload_length = Cstruct.len buf;
                  }) in
                  let header = Forwarder.Frame.Udp.write_header udp write_header_buffer in
                  write client_flow header
                  >>= fun () ->
                  write client_flow buf
                  >>= fun () ->
                  internet2vsock ()
                end in
            Lwt.pick [ vsock2internet (); internet2vsock () ]
        end
      | `Unix _ -> failwith "We don't simulate Unix paths"
      ) in
    forever

  let port =
    Host.Sockets.Stream.Tcp.bind (Ipaddr.V4 Ipaddr.V4.localhost, 0)
    >>= fun server ->
    let _, local_port = Host.Sockets.Stream.Tcp.getsockname server in
    Host.Sockets.Stream.Tcp.listen server accept;
    Lwt.return local_port

  type t = {
    local_port: int;
    server: Host.Sockets.Stream.Tcp.server;
  }
end

module Forward = Forward.Make(Mclock)(struct
    include Host.Sockets.Stream.Tcp

    open Lwt.Infix

    let connect () =
      ForwardServer.port >>= fun port ->
      Host.Sockets.Stream.Tcp.connect (Ipaddr.V4 Ipaddr.V4.localhost, port)
      >>= function
      | Error (`Msg m) -> failwith m
      | Ok x            -> Lwt.return x
  end)(Host.Sockets)

let localhost = Ipaddr.V4.localhost

module PortsServer = struct
  module Ports = Active_list.Make(Forward)
  module Server = Protocol_9p.Server.Make(Log)(Host.Sockets.Stream.Tcp)(Ports)

  let with_server f =
    let ports = Ports.make () in
    Host.Sockets.Stream.Tcp.bind (Ipaddr.V4 localhost, 0)
    >>= fun server ->
    let _, port = Host.Sockets.Stream.Tcp.getsockname server in
    Host.Sockets.Stream.Tcp.listen server
      (fun conn ->
         Server.connect ports conn ()
         >>= function
         | Error (`Msg m) ->
           Log.err (fun f -> f "failed to establish 9P connection: %s" m);
           Lwt.return ()
         | Ok server ->
           Server.after_disconnect server
      );
    f port
    >>= fun () ->
    Host.Sockets.Stream.Tcp.shutdown server
end

module LocalTCPClient = struct
  let connect (ip, port) =
    Host.Sockets.Stream.Tcp.connect (Ipaddr.V4 ip, port)
    >>= function
    | Ok fd -> Lwt.return fd
    | Error (`Msg m) -> failwith m
  let disconnect fd = Host.Sockets.Stream.Tcp.close fd
end

let read_http ch =
  let rec loop acc =
    Channel.read_line ch >>= function
    | Ok `Eof
    | Error _ -> Lwt.return acc
    | Ok (`Data bufs) ->
      let txt = Cstruct.(to_string (concat bufs)) in
      if txt = ""
      then Lwt.return acc
      else loop (acc ^ txt)
  in
  loop ""

module LocalUDPClient = struct
  let connect (ip, port) =
    Log.info (fun f -> f "LocalUDPClient.connect to port %d" port);
    Host.Sockets.Datagram.Udp.connect (Ipaddr.V4 ip, port)
    >>= function
    | Ok fd -> Lwt.return fd
    | Error (`Msg m) -> failwith m
  let disconnect fd = Host.Sockets.Datagram.Udp.close fd
end

let udp_echo t len =
  let pattern = Cstruct.create len in
  for i = 0 to Cstruct.len pattern - 1 do
    Cstruct.set_uint8 pattern i (Random.int 255)
  done;
  let sender () =
    let rec loop () =
      Log.info (fun f -> f "Sending UDP echo");
      Host.Sockets.Datagram.Udp.write t pattern
      >>= function
      | Error _ -> Lwt.fail_with "Datagram.Udp.write error"
      | Ok () ->
        Host.Time.sleep_ns (Duration.of_sec 1)
        >>= fun () ->
        loop () in
    loop () in
  let receiver () =
    Host.Sockets.Datagram.Udp.read t
    >>= function
    | Ok (`Data buf) ->
      Log.info (fun f -> f "Received UDP echo");
      if Cstruct.compare pattern buf <> 0 then begin
        Printf.printf "pattern = \n";
        Cstruct.hexdump pattern;
        Printf.printf "buf =\n";
        Cstruct.hexdump buf;
        Lwt.fail_with "udp echo corrupt"
      end else Lwt.return_unit
    | Ok `Eof ->
      Lwt.fail_with "Datagram.Udp.read `Eof"
    | Error _ ->
      Lwt.fail_with "Datagram.Udp.read Error" in
  let timeout () =
    Host.Time.sleep_ns (Duration.of_sec 5)
    >>= fun () ->
    Lwt.fail_with "udp_echo timeout" in
  Lwt.pick [ sender (); receiver (); timeout () ]

module LocalTCPServer = struct
  type t = {
    local_port: int;
    server: Host.Sockets.Stream.Tcp.server;
  }

  let accept flow =
    let ch = Channel.create flow in
    read_http ch >>= fun request ->
    if not(Astring.String.is_prefix ~affix:"GET" request)
    then failwith (Printf.sprintf "unrecognised HTTP GET: [%s]" request);
    let response = "HTTP/1.0 404 Not found\r\ncontent-length: 0\r\n\r\n" in
    Channel.write_string ch response 0 (String.length response);
    Channel.flush ch >|= function
    | Ok ()   -> ()
    | Error e -> Fmt.kstrf failwith "%a" Channel.pp_write_error e

  let create () =
    Host.Sockets.Stream.Tcp.bind (Ipaddr.V4 localhost, 0)
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

module LocalUDPServer = struct
  type t = {
    local_port: int;
    server: Host.Sockets.Datagram.Udp.server;
  }

  let echo server =
    let from_internet_buffer = Cstruct.create Constants.max_udp_length in
    let rec loop () =
      Log.info (fun f -> f "LocalUDPServer.recvfrom");
      Host.Sockets.Datagram.Udp.recvfrom server from_internet_buffer
      >>= fun (len, address) ->
      Log.info (fun f -> f "LocalUDPServer received len = %d" len);
      let buf = Cstruct.sub from_internet_buffer 0 len in
      Host.Sockets.Datagram.Udp.sendto server address buf
      >>= fun () ->
      Log.info (fun f -> f "LocalUDPServer received len = %d" len);
      loop () in
    Lwt.async
      (fun () ->
        Lwt.catch loop
        (fun _e ->
          Log.info (fun f -> f "LocalUDPServer echo shutting down");
          Lwt.return_unit
        )
      )

  let create () =
    Host.Sockets.Datagram.Udp.bind (Ipaddr.V4 localhost, 0)
    >|= fun server ->
    let _, local_port = Host.Sockets.Datagram.Udp.getsockname server in
    Log.info (fun f -> f "UDP local_port=%d" local_port);
    echo server;
    { local_port; server }

  let to_string t = Printf.sprintf "udp:127.0.0.1:%d" t.local_port
  let destroy t = Host.Sockets.Datagram.Udp.shutdown t.server
  let with_server f =
    create () >>= fun server ->
    Lwt.finalize (fun () -> f server) (fun () -> Log.info (fun f -> f "LocalUDPServer closing server socket"); destroy server)
end

module ForwardControl = struct
  module Log = (val Logs.src_log Logs.default)
  module Client = Protocol_9p.Client.Make(Log)(Host.Sockets.Stream.Tcp)

  type t = {
    ninep: Client.t
  }

  let connect ports_port =
    Host.Sockets.Stream.Tcp.connect (Ipaddr.V4 localhost, ports_port)
    >>= function
    | Error (`Msg m) -> failwith m
    | Ok flow ->
      Client.connect flow () >>*= fun ninep ->
      Lwt.return { ninep }

  let disconnect { ninep } = Client.disconnect ninep

  let with_connection ports_port f =
    connect ports_port >>= fun c ->
    Lwt.finalize (fun () -> f c) (fun () -> disconnect c)

  type forward = {
    t: t;
    fid: Protocol_9p.Types.Fid.t;
    ip: Ipaddr.V4.t;
    port: int;
  }

  let create t string =
    let mode = Protocol_9p.Types.FileMode.make ~is_directory:true
        ~owner:[`Read; `Write; `Execute] ~group:[`Read; `Execute]
        ~other:[`Read; `Execute ] () in
    Client.mkdir t.ninep [] string mode
    >>*= fun () ->
    Client.LowLevel.allocate_fid t.ninep
    >>*= fun fid ->
    Client.walk_from_root t.ninep fid [ string; "ctl" ]
    >>*= fun _walk ->
    Client.LowLevel.openfid t.ninep fid Protocol_9p.Types.OpenMode.read_write
    >>*= fun _open ->
    let buf = Cstruct.create (String.length string) in
    Cstruct.blit_from_string string 0 buf 0 (String.length string);
    Client.LowLevel.write t.ninep fid 0L buf
    >>*= fun _write ->
    Client.LowLevel.read t.ninep fid 0L 1024l
    >>*= fun read ->
    let response = Cstruct.to_string read.Protocol_9p.Response.Read.data in
    if Astring.String.is_prefix ~affix:"OK " response then begin
      let line = String.sub response 3 (String.length response - 3) in
      (* tcp:127.0.0.1:64500:tcp:127.0.0.1:64499 *)
      match Astring.String.cuts ~sep:":" line with
      | ("tcp" | "udp") :: ip :: port :: _ ->
        let port = int_of_string port in
        let ip = Ipaddr.V4.of_string_exn ip in
        Lwt.return { t; fid; ip; port }
      | _ -> failwith ("failed to parse response: " ^ line)
    end else failwith response
  let destroy { t; fid; _ } =
    Client.LowLevel.clunk t.ninep fid
    >>*= fun _clunk ->
    Lwt.return ()
  let with_forward t string f =
    create t string
    >>= fun forward ->
    Lwt.finalize (fun () -> f forward.ip forward.port) (fun () -> destroy forward)
end

let http_get flow =
  let ch = Channel.create flow in
  let message = "GET / HTTP/1.0\r\nconnection: close\r\n\r\n" in
  Channel.write_string ch message 0 (String.length message);
  Channel.flush ch >>= function
  | Error e -> Fmt.kstrf failwith "%a" Channel.pp_write_error e
  | Ok ()   ->
    Host.Sockets.Stream.Tcp.shutdown_write flow
    >>= fun () ->
    read_http ch
    >|= fun response ->
    if not(Astring.String.is_prefix ~affix:"HTTP" response)
    then failwith (Printf.sprintf "unrecognised HTTP response: [%s]" response)

let test_one_tcp_forward () =
  let t = LocalTCPServer.with_server (fun server ->
      PortsServer.with_server (fun ports_port ->
          ForwardControl.with_connection ports_port (fun connection ->
              let name = "tcp:127.0.0.1:0:" ^ LocalTCPServer.to_string server in
              ForwardControl.with_forward connection name (fun ip port ->
                  LocalTCPClient.connect (ip, port)
                  >>= fun client ->
                  http_get client
                  >>= fun () ->
                  LocalTCPClient.disconnect client
                )
            )
        )
    ) in
  run t

let test_one_udp_forward () =
  let t = LocalUDPServer.with_server (fun server ->
      PortsServer.with_server (fun ports_port ->
          ForwardControl.with_connection ports_port (fun connection ->
              let name = "udp:127.0.0.1:0:" ^ LocalUDPServer.to_string server in
              ForwardControl.with_forward connection name (fun ip port ->
                  LocalUDPClient.connect (ip, port)
                  >>= fun client ->
                  udp_echo client 512
                  >>= fun () ->
                  LocalUDPClient.disconnect client
                )
            )
        )
    ) in
  run t

let interesting_sizes = [
  (* on macOS the maximum we can send is given by $(sysctl net.inet.udp.maxdgram)
     which seems to be 9216 for me *)
  1; 4; 511; 1023; 2034; 2035; 4095; 8191; 9215; 9216;
]

let test_large_udp_forwards () =
  let t = LocalUDPServer.with_server (fun server ->
      PortsServer.with_server (fun ports_port ->
          ForwardControl.with_connection ports_port (fun connection ->
              let name = "udp:127.0.0.1:0:" ^ LocalUDPServer.to_string server in
              ForwardControl.with_forward connection name (fun ip port ->
                  LocalUDPClient.connect (ip, port)
                  >>= fun client ->
                  Lwt_list.iter_s
                    (fun size ->
                      udp_echo client size
                    ) interesting_sizes
                  >>= fun () ->
                  LocalUDPClient.disconnect client
                )
            )
        )
    ) in
  run t

let test_10_tcp_connections () =
  let t = LocalTCPServer.with_server (fun server ->
      PortsServer.with_server (fun ports_port ->
          ForwardControl.with_connection ports_port (fun connection ->
              let name = "tcp:127.0.0.1:0:" ^ LocalTCPServer.to_string server in
              ForwardControl.with_forward connection name (fun ip port ->
                  let rec loop = function
                  | 0 -> Lwt.return ()
                  | n ->
                    LocalTCPClient.connect (ip, port)
                    >>= fun client ->
                    http_get client
                    >>= fun () ->
                    LocalTCPClient.disconnect client
                    >>= fun () ->
                    loop (n - 1)
                  in
                  let start = Unix.gettimeofday () in
                  loop 10
                  >>= fun () ->
                  let time = Unix.gettimeofday () -. start in
                  (* NOTE(djs55): on my MBP this is almost immediate *)
                  if time > 1. then
                    Fmt.kstrf failwith "10 connections took %.02f (> 1) \
                                        seconds" time;
                  Lwt.return ()
                )
            )
        )
    ) in
  run t

let run_test ?(timeout=Duration.of_sec 60) t =
  let timeout =
    Host.Time.sleep_ns timeout >>= fun () ->
    Lwt.fail_with "timeout"
  in
  Host.Main.run @@ Lwt.pick [ timeout; t ]

let run ?timeout ~pcap t = run_test ?timeout (Slirp_stack.with_stack ~pcap t)

(* Test the --tcpv4-forwards gateway forwarding option *)
let test_tcpv4_forwarded_configuration () =
  let t _ stack =
    Host.Sockets.Stream.Tcp.bind (Ipaddr.V4 Ipaddr.V4.localhost, Slirp_stack.local_tcpv4_forwarded_port)
    >>= fun server ->
    Lwt.finalize
      (fun () ->
        Host.Sockets.Stream.Tcp.listen server LocalTCPServer.accept;
        let open Slirp_stack in
        Client.TCPV4.create_connection (Client.tcpv4 stack.Client.t) (primary_dns_ip, local_tcpv4_forwarded_port)
        >>= function
        | Error _ ->
          Log.err (fun f -> f "Failed to connect to gateway:%d" local_tcpv4_forwarded_port);
          failwith "http_fetch"
        | Ok flow ->
          Log.info (fun f -> f "Connected to gateway:%d" local_tcpv4_forwarded_port);
          let page = Io_page.(to_cstruct (get 1)) in
          let http_get = "GET / HTTP/1.0\nHost: dave.recoil.org\n\n" in
          Cstruct.blit_from_string http_get 0 page 0 (String.length http_get);
          let buf = Cstruct.sub page 0 (String.length http_get) in
          Client.TCPV4.write flow buf >>= function
          | Error `Closed ->
            Log.err (fun f ->
                f "EOF writing HTTP request to gateway:%d" local_tcpv4_forwarded_port);
            failwith "EOF on writing HTTP GET"
          | Error _ ->
            Log.err (fun f ->
                f "Failure writing HTTP request to gateway:%d" local_tcpv4_forwarded_port);
            failwith "Failure on writing HTTP GET"
          | Ok () ->
            let rec loop total_bytes =
              Client.TCPV4.read flow >>= function
              | Ok `Eof     -> Lwt.return total_bytes
              | Error _ ->
                Log.err (fun f ->
                    f "Failure read HTTP response from gateway:%d" local_tcpv4_forwarded_port);
                failwith "Failure on reading HTTP GET"
              | Ok (`Data buf) ->
                Log.info (fun f ->
                    f "Read %d bytes from gateway:%d" (Cstruct.len buf) local_tcpv4_forwarded_port);
                Log.info (fun f -> f "%s" (Cstruct.to_string buf));
                loop (total_bytes + (Cstruct.len buf))
            in
            loop 0 >|= fun total_bytes ->
            Log.info (fun f -> f "Response had %d total bytes" total_bytes);
    ) (fun () ->
      Host.Sockets.Stream.Tcp.shutdown server
    )
    in
    run ~pcap:"test_tcpv4_forwarded_configuration" t


let tests = [
  "Ports: 1 TCP port forward",
  [ "Perform an HTTP GET through a port forward",
    `Quick,
    test_one_tcp_forward ];

  "Ports: 10 TCP port forwards",
  [ "Perform 10 HTTP GETs through a port forward",
    `Quick,
    test_10_tcp_connections ];

  "Ports: 1 UDP port forward",
  [ "Send a UDP packet through a port forward",
    `Quick,
    test_one_udp_forward ];

  "Ports: large UDP packets through a port forward",
  [ "Send large UDP packets through a port forward",
    `Quick,
    test_large_udp_forwards ];

  "Ports: check --tcpv4-forwards option",
  [ "Connect to a local server",
    `Quick,
    test_tcpv4_forwarded_configuration ];
]

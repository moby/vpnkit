open Lwt.Infix

let src =
  let src = Logs.Src.create "tcp" ~doc:"Test TCP half-close in the proxy" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

let failf fmt = Fmt.kstrf failwith fmt

module Log = (val Logs.src_log src : Logs.LOG)

module Server = struct
  type t = {
    server: Host.Sockets.Stream.Tcp.server;
    port: int;
  }
  let create on_accept =
    Host.Sockets.Stream.Tcp.bind (Ipaddr.V4 Ipaddr.V4.localhost, 0)
    >>= fun server ->
    let _, port = Host.Sockets.Stream.Tcp.getsockname server in
    Host.Sockets.Stream.Tcp.listen server on_accept;
    Lwt.return { server; port }
  let destroy t =
    Host.Sockets.Stream.Tcp.shutdown t.server
end
let with_server on_accept f =
  Server.create on_accept
  >>= fun server ->
  Lwt.finalize (fun () -> f server) (fun () -> Server.destroy server)

module Outgoing = struct
  module C = Mirage_channel.Make(Slirp_stack.Client.TCPV4)
end
module Incoming = struct
  module C = Mirage_channel.Make(Host.Sockets.Stream.Tcp)
end

let request = "Hello there"
let response = "And hello to you"

let data = function
| Ok (`Data x) -> x
| Ok `Eof      -> failwith "data: eof"
| Error _      -> failwith "data: error"

let unit = function
| Ok ()   -> ()
| Error _ -> failwith "unit: error"

let flow ip port = function
| Ok flow -> flow
| Error _ ->
  Log.err (fun f -> f "Failed to connect to %a:%d" Ipaddr.V4.pp ip port);
  failwith "Client.TCPV4.create_connection"

(* Run a simple server on localhost and connect to it via vpnkit.
   The Mirage client will call `close` to trigger a half-close of
   the TCP connection before reading the response. This verifies
   that the other side of the connection remains open. *)
let test_mirage_half_close () =
  Host.Main.run begin
    let forwarded, forwarded_u = Lwt.task () in
    Slirp_stack.with_stack ~pcap:"test_mirage_half_close.pcap" (fun _ stack -> with_server (fun flow ->
        (* Read the request until EOF *)
        let ic = Incoming.C.create flow in
        Incoming.C.read_line ic >|= data >>= fun bufs ->
        let txt = Cstruct.(to_string @@ concat bufs) in
        if txt <> request
        then failf "Expected to read '%s', got '%s'" request txt;
        Incoming.C.read_line ic >|= data >>= fun bufs ->
        assert (Cstruct.(len @@ concat bufs) = 0);
        Log.info (fun f -> f "Read the request (up to and including EOF)");

        (* Write a response. If the connection is fully closed
           rather than half-closed then this will fail. *)
        Incoming.C.write_line ic response;
        Incoming.C.flush ic >|= unit  >>= fun () ->
        Log.info (fun f -> f "Written response");
        Lwt.wakeup_later forwarded_u ();
        Lwt.return_unit
      ) (fun server ->
        (* Now that the server is running, connect to it and send a
           request. *)
        let open Slirp_stack in
        let ip = Ipaddr.V4.localhost in
        let port = server.Server.port in
        Client.TCPV4.create_connection (Client.tcpv4 stack.t) (ip, port)
        >|= flow ip port >>= fun flow ->
        Log.info (fun f -> f "Connected to %a:%d" Ipaddr.V4.pp ip port);
        let oc = Outgoing.C.create flow in
        Outgoing.C.write_line oc request;
        Outgoing.C.flush oc >|= unit >>= fun () ->

        (* This will perform a TCP half-close *)
        Client.TCPV4.close flow >>= fun () ->

        (* Verify the response is still intact *)
        Outgoing.C.read_line oc >|= data >>= fun bufs ->
        let txt = Cstruct.(to_string @@ concat bufs) in
        if txt <> response
        then failf "Expected to read '%s', got '%s'" response txt;
        Log.info (fun f -> f "Read the response. Waiting for cleanup");
        Lwt.pick [
          (Host.Time.sleep_ns (Duration.of_sec 100) >|= fun () -> `Timeout);
          (forwarded >|= fun x -> `Result x) ]
      ) >>= function
        | `Timeout  -> failwith "TCP half close test timed-out"
        | `Result x -> Lwt.return x
      )
  end

(* Run a simple server on localhost and connect to it via vpnkit.
   The server on the host will call `close` to trigger a half-close
   of the TCP connection before reading the response. This verifies
   that the other side of the connection remains open. *)
let test_host_half_close () =
  Host.Main.run begin
    let forwarded, forwarded_u = Lwt.task () in
    Slirp_stack.with_stack ~pcap:"test_host_half_close.pcap" (fun _ stack -> with_server (fun flow ->
        (* Write a request *)
        let ic = Incoming.C.create flow in
        Incoming.C.write_line ic request;
        Incoming.C.flush ic >|= unit >>= fun () ->

        (* This will perform a TCP half-close *)
        Host.Sockets.Stream.Tcp.shutdown_write flow >>= fun () ->

        (* Read the response from the other side of the connection *)
        Incoming.C.read_line ic >|= data
        >>= fun bufs ->
        let txt = Cstruct.(to_string @@ concat bufs) in
        if txt <> response
        then failf "Expected to read '%s', got '%s'" response txt;
        Log.info (fun f -> f "Read the response, signalling complete");
        Lwt.wakeup_later forwarded_u ();
        Lwt.return_unit
      ) (fun server ->
        (* Now that the server is running, connect to it and send a
           request. *)
        let open Slirp_stack in
        let ip = Ipaddr.V4.localhost in
        let port = server.Server.port in
        Client.TCPV4.create_connection (Client.tcpv4 stack.t) (ip, port)
        >|= flow ip port >>= fun flow ->
        Log.info (fun f -> f "Connected to %a:%d" Ipaddr.V4.pp ip port);
        let oc = Outgoing.C.create flow in
        (* Read the request *)
        Outgoing.C.read_line oc >|= data >>= fun bufs ->
        let txt = Cstruct.(to_string @@ concat bufs) in
        if txt <> request
        then failf "Expected to read '%s', got '%s'" request txt;
        (* Check we're at EOF *)
        Outgoing.C.read_line oc >|= data >>= fun bufs ->
        assert (Cstruct.(len @@ concat bufs) = 0);
        Log.info (fun f -> f "Read the request (up to and including EOF)");
        (* Write response *)
        Outgoing.C.write_line oc response;
        Outgoing.C.flush oc >|= unit >>= fun () ->
        Log.info (fun f -> f "Written response and will wait.");
        Lwt.pick [
          (Host.Time.sleep_ns (Duration.of_sec 100) >|= fun () -> `Timeout);
          (forwarded >|= fun x -> `Result x) ]
      ) >>= function
        | `Timeout  -> failwith "TCP half close test timed-out"
        | `Result x -> Lwt.return x
      )
  end

let tests = [

  "TCP: test Mirage half close", [
    "check that Mirage half-close isn't a full-close", `Quick,
    test_mirage_half_close
  ] ;

  "TCP: test Host half close", [
    "check that the Host half-close isn't a full-close", `Quick,
    test_host_half_close
  ];
]

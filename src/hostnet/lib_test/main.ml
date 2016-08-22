open Hostnet
open Lwt.Infix

let src =
  let src = Logs.Src.create "test" ~doc:"Test the slirp stack" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Make(Host: Sig.HOST) = struct

module Slirp_stack = Slirp_stack.Make(Host)
open Slirp_stack

let test_dhcp_query () =
  let t =
    with_stack
      (fun stack ->
        let ips = List.map Ipaddr.V4.to_string (Client.IPV4.get_ip (Client.ipv4 stack)) in
        Log.info (fun f -> f "Got an IP: %s" (String.concat ", " ips));
        Lwt.return ()
      ) in
  Host.Main.run t

let test_dns_query server () =
  let t =
    with_stack
      (fun stack ->
        let resolver = DNS.create stack in
        DNS.gethostbyname ~server resolver "www.google.com"
        >>= function
        | (_ :: _) as ips ->
          Log.info (fun f -> f "www.google.com has IPs: %s" (String.concat ", " (List.map Ipaddr.to_string ips)));
          Lwt.return ()
        | _ ->
          Log.err (fun f -> f "Failed to lookup www.google.com");
          failwith "Failed to lookup www.google.com"
      ) in
  Host.Main.run t

let test_etc_hosts_query server () =
  let test_name = "vpnkit.is.cool.yes.really" in
  let t =
    with_stack
      (fun stack ->
        let resolver = DNS.create stack in
        DNS.gethostbyname ~server resolver test_name
        >>= function
        | (_ :: _) as ips ->
          Log.err (fun f -> f "This test relies on the name %s not existing but it really has IPs: %s" test_name (String.concat ", " (List.map Ipaddr.to_string ips)));
          failwith (Printf.sprintf "Test name %s really does exist" test_name)
        | _ -> begin
          Hostnet.Hosts.etc_hosts := [
            test_name, Ipaddr.V4 (Ipaddr.V4.localhost);
          ];
          DNS.gethostbyname ~server resolver test_name
          >>= function
          | (_ :: _) as ips ->
            Log.info (fun f -> f "Name %s has IPs: %s" test_name (String.concat ", " (List.map Ipaddr.to_string ips)));
            Hostnet.Hosts.etc_hosts := [];
            Lwt.return ()
          | _ ->
            Log.err (fun f -> f "Failed to lookup name from /etc/hosts");
            Hostnet.Hosts.etc_hosts := [];
            failwith "failed to lookup name from /etc/hosts"
          end
      ) in
  Host.Main.run t

let test_max_connections () =
  let t =
    with_stack
      (fun stack ->
        Lwt.finalize
          (fun () ->
            let resolver = DNS.create stack in
            DNS.gethostbyname ~server:primary_dns_ip resolver "www.google.com"
            >>= function
            | Ipaddr.V4 ip :: _ ->
              Host.Sockets.set_max_connections (Some 0);
              begin Client.TCPV4.create_connection (Client.tcpv4 stack) (ip, 80)
              >>= function
              | `Ok flow ->
                Log.err (fun f -> f "Connected to www.google.com, max_connections exceeded");
                failwith "too many connections"
              | `Error _ ->
                Log.debug (fun f -> f "Expected failure to connect to www.google.com");
                Lwt.return ()
              end
            | _ ->
              Log.err (fun f -> f "Failed to look up an IPv4 address for www.google.com");
              failwith "http_fetch dns"
          ) (fun () ->
            Host.Sockets.set_max_connections None;
            Lwt.return_unit
          )
      ) in
  Host.Main.run t

let test_http_fetch () =
  let t =
    with_stack
      (fun stack ->
        let resolver = DNS.create stack in
        DNS.gethostbyname resolver "www.google.com"
        >>= function
        | Ipaddr.V4 ip :: _ ->
          begin Client.TCPV4.create_connection (Client.tcpv4 stack) (ip, 80)
          >>= function
          | `Ok flow ->
            Log.info (fun f -> f "Connected to www.google.com:80");
            let page = Io_page.(to_cstruct (get 1)) in
            let http_get = "GET / HTTP/1.0\nHost: anil.recoil.org\n\n" in
            Cstruct.blit_from_string http_get 0 page 0 (String.length http_get);
            let buf = Cstruct.sub page 0 (String.length http_get) in
            begin Client.TCPV4.write flow buf >>= function
            | `Eof     ->
              Log.err (fun f -> f "EOF writing HTTP request to www.google.com:80");
              failwith "EOF on writing HTTP GET"
            | `Error _ ->
              Log.err (fun f -> f "Failure writing HTTP request to www.google.com:80");
              failwith "Failure on writing HTTP GET"
            | `Ok _buf ->
              let rec loop total_bytes =
                Client.TCPV4.read flow >>= function
                | `Eof ->
                  Lwt.return total_bytes
                | `Error _ ->
                  Log.err (fun f -> f "Failure read HTTP response from www.google.com:80");
                  failwith "Failure on reading HTTP GET"
                | `Ok buf ->
                  Log.info (fun f -> f "Read %d bytes from www.google.com:80" (Cstruct.len buf));
                  Log.info (fun f -> f "%s" (Cstruct.to_string buf));
                  loop (total_bytes + (Cstruct.len buf)) in
              loop 0
              >>= fun total_bytes ->
              Log.info (fun f -> f "Response had %d total bytes" total_bytes);
              if total_bytes == 0 then failwith "response was empty";
              Lwt.return ()
            end
          | `Error _ ->
            Log.err (fun f -> f "Failed to connect to www.google.com:80");
            failwith "http_fetch"
          end
        | _ ->
          Log.err (fun f -> f "Failed to look up an IPv4 address for www.google.com");
          failwith "http_fetch dns"
      ) in
  Host.Main.run t

module DevNullServer = struct
  (* Accept local TCP connections, throw away all incoming data and then return
     the total number of bytes processed. *)
  type t = {
    local_port: int;
    server: Host.Sockets.Stream.Tcp.server;
  }

  let accept flow =
    let module Channel = Channel.Make(Host.Sockets.Stream.Tcp) in
    let ch = Channel.create flow in
    (* XXX: this looks like it isn't tail recursive to me *)
    let rec drop_all_data count =
      Lwt.catch
        (fun () ->
          Channel.read_some ch
          >>= fun buffer ->
          drop_all_data Int64.(add count (of_int (Cstruct.len buffer)))
        ) (function
          | End_of_file ->
            Lwt.return count
          | e ->
            Lwt.fail e
          ) in
    drop_all_data 0L
    >>= fun total ->
    let response = Cstruct.create 8 in
    Cstruct.LE.set_uint64 response 0 total;
    Channel.write_buffer ch response;
    Channel.flush ch

  let create () =
    Host.Sockets.Stream.Tcp.bind (Ipaddr.V4.localhost, 0)
    >>= fun server ->
    let _, local_port = Host.Sockets.Stream.Tcp.getsockname server in
    Host.Sockets.Stream.Tcp.listen server accept;
    Lwt.return { local_port; server }

  let to_string t =
    Printf.sprintf "tcp:127.0.0.1:%d" t.local_port
  let destroy t = Host.Sockets.Stream.Tcp.shutdown t.server
  let with_server f =
    create ()
    >>= fun server ->
    Lwt.finalize
      (fun () ->
        f server
      ) (fun () ->
        destroy server
      )
end

let rec count = function 0 -> [] | n -> () :: (count (n - 1))

let test_stream_data connections length () =
  let t =
    DevNullServer.with_server
      (fun { DevNullServer.local_port } ->
        with_stack
          (fun stack ->
            Lwt_list.iter_p
              (fun () ->
                let rec connect () =
                  Client.TCPV4.create_connection (Client.tcpv4 stack) (Ipaddr.V4.localhost, local_port)
                  >>= function
                  | `Error `Refused ->
                    Log.info (fun f -> f "DevNullServer Refused connection");
                    Host.Time.sleep 0.2
                    >>= fun () ->
                    connect ()
                  | `Error `Timeout ->
                    Log.err (fun f -> f "DevNullServer connection timeout");
                    failwith "DevNullServer connection timeout";
                  | `Error (`Unknown x) ->
                    Log.err (fun f -> f "DevNullServer connnection failure: %s" x);
                    failwith x
                  | `Ok flow ->
                    Log.info (fun f -> f "Connected to local server");
                    Lwt.return flow in
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
                      | `Eof     ->
                        Log.err (fun f -> f "EOF writing to DevNullServerwith %d bytes left" remaining);
                        (* failwith "EOF on writing to DevNullServer" *)
                        Lwt.return ()
                      | `Error _ ->
                        Log.err (fun f -> f "Failure writing to DevNullServer with %d bytes left" remaining);
                        (* failwith "Failure on writing to DevNullServer" *)
                        Lwt.return ()
                      | `Ok () ->
                        loop (remaining - this_time)
                    end in
                  loop length
                  >>= fun () ->
                  Client.TCPV4.close flow
                  >>= fun () ->
                  Client.TCPV4.read flow >>= function
                  | `Eof ->
                    Log.err (fun f -> f "EOF reading result from DevNullServer");
                    (* failwith "EOF reading result from DevNullServer" *)
                    Lwt.return ()
                  | `Error _ ->
                    Log.err (fun f -> f "Failure reading result from DevNullServer");
                    (* failwith "Failure on reading result from DevNullServer" *)
                    Lwt.return ()
                  | `Ok buf ->
                    Log.info (fun f -> f "Read %d bytes from DevNullServer" (Cstruct.len buf));
                    let response = Cstruct.LE.get_uint64 buf 0 in
                    if Int64.to_int response != length
                    then failwith (Printf.sprintf "Response was %Ld while expected %d" response length);
                    Lwt.return ()
                ) (count connections)
          )
      ) in
  Host.Main.run t

let test_dhcp = [
  "Simple query", `Quick, test_dhcp_query;
]

let test_dns = [
  "Use 8.8.8.8 to lookup www.google.com", `Quick, test_dns_query primary_dns_ip;
  "Service a query from /etc/hosts cache", `Quick, test_etc_hosts_query primary_dns_ip;
] @ (List.map (fun ip ->
  "Use 8.8.8.8 to lookup www.google.com via " ^ (Ipaddr.V4.to_string ip), `Quick, test_dns_query ip;
  ) extra_dns_ip
)

let test_tcp = [
  "HTTP GET http://www.google.com/", `Quick, test_http_fetch;
  "HTTP GET fails beyond max connections", `Quick, test_max_connections;
  "1 TCP connection transferring 1 KiB", `Quick, test_stream_data 1 1024;
  (*
  "10 TCP connections each transferring 1 KiB", `Quick, test_stream_data 10 1024;
  "32 TCP connections each transferring 1 KiB", `Quick, test_stream_data 32 1024;
  "1 TCP connection transferring 1 MiB", `Quick, test_stream_data 1 (1024*1024);
  "32 TCP connections each transferring 1 MiB", `Quick, test_stream_data 32 (1024*1024);
  "1 TCP connection transferring 1 GiB", `Slow, test_stream_data 1 (1024*1024*1024);
  "32 TCP connections each transferring 1 GiB", `Slow, test_stream_data 32 (1024*1024*1024);
  *)
]

module F = Forwarding.Make(Host)
module N = Nat.Make(Host)

let suite = [
  "DHCP", test_dhcp;
  "DNS UDP", test_dns;
  "TCP", test_tcp;
  "Forwarding", F.test;
  "UDP", N.suite;
]
end

module Slirp_lwt_unix = Make(Host_lwt_unix)
module Slirp_uwt = Make(Host_uwt)

let tests =
  (List.map (fun (name, test) -> name ^ " with Lwt_unix", test) Slirp_lwt_unix.suite) @
  (List.map (fun (name, test) -> name ^ " with Uwt", test) Slirp_uwt.suite) @
  Resolver_test.suite @
  Hosts_test.suite

(* Run it *)
let () =
  Logs.set_reporter (Logs_fmt.reporter ());
  Lwt.async_exception_hook := (fun exn ->
    Log.err (fun f -> f "Lwt.async failure %s: %s"
      (Printexc.to_string exn)
      (Printexc.get_backtrace ())
    )
  );
  Alcotest.run "Hostnet" tests

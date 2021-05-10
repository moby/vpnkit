open Lwt.Infix

let src =
  let src = Logs.Src.create "http" ~doc:"Test the HTTP proxy" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Exclude = struct

  let test_ip_match () =
    let exclude = Hostnet_http.Exclude.of_string "10.0.0.1" in
    assert (Hostnet_http.Exclude.matches "10.0.0.1" exclude)

  let test_cidr_match () =
    let exclude = Hostnet_http.Exclude.of_string "10.0.0.0/24" in
    assert (Hostnet_http.Exclude.matches "10.0.0.1" exclude)

  let test_cidr_no_match () =
    let exclude = Hostnet_http.Exclude.of_string "10.0.0.0/24" in
    assert (not(Hostnet_http.Exclude.matches
                  "192.168.0.1"
                  exclude))

  let test_domain_match () =
    let exclude = Hostnet_http.Exclude.of_string "mit.edu" in
    assert (Hostnet_http.Exclude.matches
                  "dave.mit.edu"
                  exclude)

  let test_domain_star_match () =
    let exclude = Hostnet_http.Exclude.of_string "*.mit.edu" in
    assert (Hostnet_http.Exclude.matches
                  "dave.mit.edu"
                  exclude)

  let test_domain_dot_match () =
    let exclude = Hostnet_http.Exclude.of_string ".mit.edu" in
    assert (Hostnet_http.Exclude.matches
                  "dave.mit.edu"
                  exclude)

  let test_domain_no_match () =
    let exclude = Hostnet_http.Exclude.of_string "mit.edu" in
    assert (not(Hostnet_http.Exclude.matches
                  "www.mobyproject.org"
                  exclude))

  let test_list () =
    let exclude = Hostnet_http.Exclude.of_string "*.local, 169.254.0.0/16" in
    assert (Hostnet_http.Exclude.matches
                  "dave.local"
                  exclude);
    assert (Hostnet_http.Exclude.matches
                  "169.254.0.1"
                  exclude);
    assert (not(Hostnet_http.Exclude.matches
                  "10.0.0.1"
                  exclude));
    assert (not(Hostnet_http.Exclude.matches
                  "www.mobyproject.org"
                  exclude))

  let tests = [
    "HTTP: no_proxy IP match", [ "", `Quick, test_ip_match ];
    "HTTP: no_proxy CIDR match", [ "", `Quick, test_cidr_match ];
    "HTTP: no_proxy CIDR no match", [ "", `Quick, test_cidr_no_match ];
    "HTTP: no_proxy domain match", [ "", `Quick, test_domain_match ];
    "HTTP: no_proxy domain no match", [ "", `Quick, test_domain_no_match ];
    "HTTP: no_proxy domain star match", [ "", `Quick, test_domain_star_match ];
    "HTTP: no_proxy domain dot match", [ "", `Quick, test_domain_dot_match ];
    "HTTP: no_proxy list", [ "", `Quick, test_list ];
  ]
end

module Server = struct
  type t = {
    server: Host.Sockets.Stream.Tcp.server;
    port: int;
  }
  let create on_accept =
    Host.Sockets.Stream.Tcp.bind (Ipaddr.V4 Ipaddr.V4.localhost, 0)
    >>= fun server ->
    Host.Sockets.Stream.Tcp.getsockname server
    >>= fun (_, port) ->
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
  module C = Mirage_channel_lwt.Make(Slirp_stack.Client.TCPV4)
  module IO = Cohttp_mirage_io.Make(C)
  module Request = Cohttp.Request.Make(IO)
  module Response = Cohttp.Response.Make(IO)
end
module Incoming = struct
  module C = Mirage_channel_lwt.Make(Host.Sockets.Stream.Tcp)
  module IO = Cohttp_mirage_io.Make(C)
  module Request = Cohttp.Request.Make(IO)
  module Response = Cohttp.Response.Make(IO)
end

let send_http_request stack (ip, port) request =
  let open Slirp_stack in
  Client.TCPV4.create_connection (Client.tcpv4 stack) (ip, port)
  >>= function
  | Ok flow ->
    Log.info (fun f -> f "Connected to %s:80" (Ipaddr.V4.to_string ip));
    let oc = Outgoing.C.create flow in
    Outgoing.Request.write ~flush:true (fun _writer -> Lwt.return_unit)
      request oc
  | Error _ ->
    Log.err (fun f -> f "Failed to connect to %s:80" (Ipaddr.V4.to_string ip));
    failwith "http_fetch"

let intercept ~pcap ?(port = 80) proxy request =
  let forwarded, forwarded_u = Lwt.task () in
  Slirp_stack.with_stack ~pcap (fun _ stack ->
      with_server (fun flow ->
          let ic = Incoming.C.create flow in
          Incoming.Request.read ic >>= function
          | `Eof ->
            Log.err (fun f -> f "Failed to request");
            failwith "Failed to read request"
          | `Invalid x ->
            Log.err (fun f -> f "Failed to parse request: %s" x);
            failwith ("Failed to parse request: " ^ x)
          | `Ok req ->
            (* parse the response *)
            Lwt.wakeup_later forwarded_u req;
            Lwt.return_unit
        ) (fun server ->
          let json =
            Ezjsonm.from_string (" { \"http\": \"" ^ proxy ^ ":" ^
                                 (string_of_int server.Server.port) ^ "\" }")
          in
          Slirp_stack.Slirp_stack.Debug.update_http_json json ()
          >>= function
          | Error (`Msg m) -> failwith ("Failed to enable HTTP proxy: " ^ m)
          | Ok () ->
            send_http_request stack.t (Ipaddr.V4.of_string_exn "127.0.0.1", port)
              request
            >>= fun () ->
            Lwt.pick [
              (Host.Time.sleep_ns (Duration.of_sec 100) >|= fun () ->
               `Timeout);
              (forwarded >>= fun x -> Lwt.return (`Result x))
            ]
        )
      >|= function
      | `Timeout  -> failwith "HTTP interception failed"
      | `Result x -> x
    )

(* Test that HTTP interception works at all *)
let test_interception proxy () =
  Host.Main.run begin
    let request =
      Cohttp.Request.make
        (Uri.make ~scheme:"http" ~host:"www.mobyproject.org" ~path:"/" ())
    in
    intercept ~pcap:"test_interception.pcap" proxy request >>= fun result ->
    Log.info (fun f ->
        f "original was: %s"
          (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t request)));
    Log.info (fun f ->
        f "proxied  was: %s"
          (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t result)));
    Alcotest.check Alcotest.string "method"
      (Cohttp.Code.string_of_method request.Cohttp.Request.meth)
      (Cohttp.Code.string_of_method result.Cohttp.Request.meth);
    Alcotest.check Alcotest.string "version"
      (Cohttp.Code.string_of_version request.Cohttp.Request.version)
      (Cohttp.Code.string_of_version result.Cohttp.Request.version);
    (* a request to a proxy must have an absolute URI *)
    Alcotest.check Alcotest.string "uri"
      "http://www.mobyproject.org:80/"
      result.Cohttp.Request.resource;
    Alcotest.check Alcotest.(list(pair string string)) "headers"
      (Cohttp.Header.to_list request.Cohttp.Request.headers)
      (Cohttp.Header.to_list result.Cohttp.Request.headers);
    Lwt.return ()
  end

(* Test that a relative URI becomes absolute *)
let test_uri_relative proxy () =
  Host.Main.run begin
    let request =
      Cohttp.Request.make
        (Uri.make ~scheme:"http" ~host:"www.mobyproject.org" ~path:"/" ())
    in
    intercept ~pcap:"test_uri_relative.pcap" proxy request >>= fun result ->
    Log.info (fun f ->
        f "original was: %s"
          (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t request)));
    Log.info (fun f ->
        f "proxied  was: %s"
          (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t result)));
    let uri = Uri.of_string result.Cohttp.Request.resource in
    Alcotest.check Alcotest.(option string) "scheme"
      (Some "http") (Uri.scheme uri);
    Lwt.return ()
  end

(* Test that an absolute URI is preserved. This is expected when the
   client explicitly uses us as a proxy rather than being transparent. *)
let test_uri_absolute proxy () =
  Host.Main.run begin
    let request =
      Cohttp.Request.make
        (Uri.make ~host:"www.mobyproject.org" ~path:"/" ())
    in
    intercept ~pcap:"test_uri_absolute.pcap" proxy request >>= fun result ->
    Log.info (fun f ->
        f "original was: %s"
          (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t request)));
    Log.info (fun f ->
        f "proxied  was: %s"
          (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t result)));
    let uri = Uri.of_string result.Cohttp.Request.resource in
    Alcotest.check Alcotest.(option string) "scheme"
      (Some "http") (Uri.scheme uri);
    Lwt.return ()
  end

(* Verify that a custom X- header is preserved *)
let test_x_header_preserved proxy () =
  Host.Main.run begin
    let headers =
      Cohttp.Header.add (Cohttp.Header.init ()) "X-dave-is-cool" "true"
    in
    let request =
      Cohttp.Request.make ~headers
        (Uri.make ~scheme:"http" ~host:"www.mobyproject.org" ~path:"/" ())
    in
    intercept ~pcap:"test_x_header_preserved.pcap" proxy request >>= fun result ->
    Log.info (fun f ->
        f "original was: %s"
          (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t request)));
    Log.info (fun f ->
        f "proxied  was: %s"
          (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t result)));
    Alcotest.check Alcotest.(option string) "X-header"
      (Some "true")
      (Cohttp.Header.get result.Cohttp.Request.headers "X-dave-is-cool");
    Lwt.return ()
  end

(* Verify that the user-agent is preserved. In particular we don't want our
   http library to leak here. *)
let test_user_agent_preserved proxy () =
  Host.Main.run begin
    let headers =
      Cohttp.Header.add (Cohttp.Header.init ()) "user-agent" "whatever"
    in
    let request =
      Cohttp.Request.make ~headers
        (Uri.make ~scheme:"http" ~host:"www.mobyproject.org" ~path:"/" ())
    in
    intercept ~pcap:"test_user_agent_preserved.pcap" proxy request >>= fun result ->
    Log.info (fun f ->
        f "original was: %s"
          (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t request)));
    Log.info (fun f ->
        f "proxied  was: %s"
          (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t result)));
    Alcotest.check Alcotest.(option string) "user-agent" (Some "whatever")
      (Cohttp.Header.get result.Cohttp.Request.headers "user-agent");
    Lwt.return ()
  end

(* Verify that authorizations are preserved *)
let test_authorization_preserved proxy () =
  Host.Main.run begin
    let headers =
      Cohttp.Header.add (Cohttp.Header.init ()) "authorization" "basic foobar"
    in
    let request =
      Cohttp.Request.make ~headers
        (Uri.make ~scheme:"http" ~host:"www.mobyproject.org" ~path:"/" ())
    in
    intercept ~pcap:"test_authorization_preserved.pcap" proxy request >>= fun result ->
    Log.info (fun f ->
        f "original was: %s"
          (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t request)));
    Log.info (fun f ->
        f "proxied  was: %s"
          (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t result)));
    Alcotest.check Alcotest.(option string) "authorization" (Some "basic foobar")
      (Cohttp.Header.get result.Cohttp.Request.headers "authorization");
    Lwt.return ()
  end

(* Verify that necessary proxy authorizations are present *)
let test_proxy_authorization proxy () =
  Host.Main.run begin
    let headers =
      Cohttp.Header.add (Cohttp.Header.init ()) "authorization" "basic foobar"
    in
    let request =
      Cohttp.Request.make ~headers
        (Uri.make ~scheme:"http" ~host:"www.mobyproject.org" ~path:"/" ())
    in
    intercept ~pcap:"test_proxy_authorization.pcap" proxy request >>= fun result ->
    Log.info (fun f ->
        f "original was: %s"
          (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t request)));
    Log.info (fun f ->
        f "proxied  was: %s"
          (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t result)));
    (* If the proxy uses auth, then there has to be a Proxy-Authorization
       header. If theres no auth, there should be no header. *)
    let proxy_authorization = "proxy-authorization" in
    let proxy = Uri.of_string proxy in
    begin match Uri.user proxy, Uri.password proxy with
    | Some username, Some password ->
      Alcotest.check Alcotest.(list string) proxy_authorization
        (result.Cohttp.Request.headers |> Cohttp.Header.to_list |> List.filter (fun (k, _) -> k = proxy_authorization) |> List.map snd)
        [ "Basic " ^ (Base64.encode_exn (username ^ ":" ^ password)) ]
    | _, _ ->
      Alcotest.check Alcotest.(list string) proxy_authorization
        (result.Cohttp.Request.headers |> Cohttp.Header.to_list |> List.filter (fun (k, _) -> k = proxy_authorization) |> List.map snd)
        [ ]
    end;
    Lwt.return ()
  end

let err_flush e = Fmt.kstrf failwith "%a" Incoming.C.pp_write_error e

let test_http_connect_tunnel proxy () =
  let test_dst_ip = Ipaddr.V4.of_string_exn "1.2.3.4" in
  Host.Main.run begin
    Slirp_stack.with_stack ~pcap:"test_http_connect.pcap" (fun _ stack ->
        with_server (fun flow ->
            let ic = Incoming.C.create flow in
            Incoming.Request.read ic >>= function
            | `Eof ->
              Log.err (fun f -> f "Failed to request");
              failwith "Failed to read request"
            | `Invalid x ->
              Log.err (fun f -> f "Failed to parse request: %s" x);
              failwith ("Failed to parse request: " ^ x)
            | `Ok req ->
              Log.info (fun f ->
                  f "received: %s"
                    (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t req)));
              Alcotest.check Alcotest.string "method"
                (Cohttp.Code.string_of_method `CONNECT)
                (Cohttp.Code.string_of_method req.Cohttp.Request.meth);
              let uri = Cohttp.Request.uri req in
              Alcotest.check Alcotest.(option string) "host"
                (Some (Ipaddr.V4.to_string test_dst_ip)) (Uri.host uri);
              Alcotest.check Alcotest.(option int) "port" (Some 443)
                (Uri.port uri);
              Alcotest.check Alcotest.(option string) "host"
                (Some (Ipaddr.V4.to_string test_dst_ip ^ ":443"))
                (Cohttp.Header.get req.Cohttp.Request.headers "host");
              Alcotest.check Alcotest.string "resource"
                (Ipaddr.V4.to_string test_dst_ip ^ ":443")
                req.Cohttp.Request.resource;
              (* If the proxy uses auth, then there has to be a Proxy-Authorization
                 header. If theres no auth, there should be no header. *)
              let proxy_authorization = "proxy-authorization" in
              begin match Uri.user proxy, Uri.password proxy with
              | Some username, Some password ->
                Alcotest.check Alcotest.(list string) proxy_authorization
                  (req.Cohttp.Request.headers |> Cohttp.Header.to_list |> List.filter (fun (k, _) -> k = proxy_authorization) |> List.map snd)
                  [ "Basic " ^ (Base64.encode_exn (username ^ ":" ^ password)) ]
              | _, _ ->
                Alcotest.check Alcotest.(list string) proxy_authorization
                  (req.Cohttp.Request.headers |> Cohttp.Header.to_list |> List.filter (fun (k, _) -> k = proxy_authorization) |> List.map snd)
                  [ ]
              end;
              (* Unfortunately cohttp always adds transfer-encoding: chunked
                 so we write the header ourselves *)
              Incoming.C.write_line ic "HTTP/1.0 200 OK\r";
              Incoming.C.write_line ic "\r";
              Incoming.C.flush ic >>= function
              | Error e -> err_flush e
              | Ok ()   ->
                Incoming.C.write_line ic "hello";
                Incoming.C.flush ic >|= function
                | Error e -> err_flush e
                | Ok ()   -> ()
          ) (fun server ->
            Slirp_stack.Slirp_stack.Debug.update_http
              ~https:(Uri.(to_string @@ with_port proxy (Some server.Server.port))) ()
            >>= function
            | Error (`Msg m) -> failwith ("Failed to enable HTTP proxy: " ^ m)
            | Ok () ->
              let open Slirp_stack in
              Client.TCPV4.create_connection (Client.tcpv4 stack.t)
                (test_dst_ip, 443)
              >>= function
              | Error _ ->
                Log.err (fun f ->
                    f "TCPV4.create_connection %a:443 failed"
                      Ipaddr.V4.pp test_dst_ip);
                failwith "TCPV4.create_connection"
              | Ok flow ->
                let ic = Outgoing.C.create flow in
                Outgoing.C.read_some ~len:5 ic >>= function
                | Error e -> Fmt.kstrf failwith "%a" Outgoing.C.pp_error e
                | Ok `Eof -> failwith "EOF"
                | Ok (`Data buf) ->
                  let txt = Cstruct.to_string buf in
                  Alcotest.check Alcotest.string "message" "hello" txt;
                  Lwt.return_unit
          )
      )
  end

  let test_http_connect_forward proxy () =
    (* Run a proxy, send an HTTP CONNECT to it, check the forwarded request *)
    let proxy_port = ref 0 in
    Host.Main.run begin
      Slirp_stack.with_stack ~pcap:"test_http_connect_forward.pcap" (fun _ stack ->
          with_server (fun flow ->
              let ic = Incoming.C.create flow in
              Incoming.Request.read ic >>= function
              | `Eof ->
                Log.err (fun f -> f "Failed to request");
                failwith "Failed to read request"
              | `Invalid x ->
                Log.err (fun f -> f "Failed to parse request: %s" x);
                failwith ("Failed to parse request: " ^ x)
              | `Ok req ->
                Log.info (fun f ->
                    f "received: %s"
                      (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t req)));
                Alcotest.check Alcotest.string "method"
                  (Cohttp.Code.string_of_method `CONNECT)
                  (Cohttp.Code.string_of_method req.Cohttp.Request.meth);
                Printf.fprintf stderr "Headers =\n  %s\n%!" (String.concat "\n  " (List.map (fun (k, v) -> k ^ ": " ^ v) (Cohttp.Header.to_list req.Cohttp.Request.headers)));
                Alcotest.check Alcotest.(option string) "host"
                  (Some ("localhost:" ^ (string_of_int !proxy_port)))
                  (Cohttp.Header.get req.Cohttp.Request.headers "host");
                Alcotest.check Alcotest.string "resource"
                  ("localhost:" ^ (string_of_int !proxy_port))
                  req.Cohttp.Request.resource;
                (* If the proxy uses auth, then there has to be a Proxy-Authorization
                   header. If theres no auth, there should be no header. *)
                let proxy_authorization = "proxy-authorization" in
                begin match Uri.user proxy, Uri.password proxy with
                | Some username, Some password ->
                  Alcotest.check Alcotest.(list string) proxy_authorization
                    [ "Basic " ^ (Base64.encode_exn (username ^ ":" ^ password)) ]
                    (req.Cohttp.Request.headers |> Cohttp.Header.to_list |> List.filter (fun (k, _) -> k = proxy_authorization) |> List.map snd)
                | _, _ ->
                  Alcotest.check Alcotest.(list string) proxy_authorization
                    [ ]
                    (req.Cohttp.Request.headers |> Cohttp.Header.to_list |> List.filter (fun (k, _) -> k = proxy_authorization) |> List.map snd)
                end;
                (* Unfortunately cohttp always adds transfer-encoding: chunked
                   so we write the header ourselves *)
                Incoming.C.write_line ic "HTTP/1.0 200 OK\r";
                Incoming.C.write_line ic "\r";
                Incoming.C.flush ic >>= function
                | Error e -> err_flush e
                | Ok ()   ->
                  Incoming.C.write_line ic "hello";
                  Incoming.C.flush ic >|= function
                  | Error e -> err_flush e
                  | Ok ()   -> ()
            ) (fun server ->
              proxy_port := server.Server.port;
              Slirp_stack.Slirp_stack.Debug.update_http
                ~https:(Uri.(to_string @@ with_port proxy (Some server.Server.port))) ()
              >>= function
              | Error (`Msg m) -> failwith ("Failed to enable HTTP proxy: " ^ m)
              | Ok () ->
                let open Slirp_stack in
                Client.TCPV4.create_connection (Client.tcpv4 stack.t)
                  (primary_dns_ip, 3129)
                >>= function
                | Error _ ->
                  Log.err (fun f ->
                      f "TCPV4.create_connection %s:%d failed"
                        (Ipaddr.V4.to_string primary_dns_ip) 3129);
                  failwith "TCPV4.create_connection"
                | Ok flow ->
                  let oc = Outgoing.C.create flow in
                  let request =
                    let connect = Cohttp.Request.make ~meth:`CONNECT (Uri.make ()) in
                    let resource = Fmt.strf "localhost:%d" server.Server.port in
                    let headers = Cohttp.Header.replace connect.Cohttp.Request.headers "host" resource in
                    { connect with Cohttp.Request.resource; headers }
                  in
                  Outgoing.Request.write ~flush:true (fun _writer -> Lwt.return_unit) request oc
                  >>= fun () ->
                  Outgoing.Response.read oc
                  >>= function
                  | `Eof ->
                    failwith "test_http_connect_forward: EOF on HTTP CONNECT"
                  | `Invalid x ->
                    failwith ("test_http_connect_forward: Invalid HTTP response: " ^ x)
                  | `Ok res ->
                    if res.Cohttp.Response.status <> `OK
                    then failwith "test_http_connect_forward: HTTP CONNECT failed";
                    Outgoing.C.read_some ~len:5 oc >>= function
                    | Error e -> Fmt.kstrf failwith "%a" Outgoing.C.pp_error e
                    | Ok `Eof -> failwith "EOF"
                    | Ok (`Data buf) ->
                      let txt = Cstruct.to_string buf in
                      Alcotest.check Alcotest.string "message" "hello" txt;
                      Lwt.return_unit
            )
      )
    end

  let test_http_proxy_connect () =
    let forwarded, forwarded_u = Lwt.task () in
    Host.Main.run begin
    Slirp_stack.with_stack ~pcap:"test_http_proxy_connect.pcap" (fun _ stack ->
        with_server (fun flow ->
            let ic = Incoming.C.create flow in
            (* read something *)
            Incoming.C.read_some ~len:5 ic
            >>= function
            | Ok `Eof -> failwith "http_proxy_connect: read_some returned Eof"
            | Error _ -> failwith "http_proxy_connect: read_some returned Error"
            | Ok (`Data buf) ->
              let txt = Cstruct.to_string buf in
              Alcotest.check Alcotest.string "message" "hello" txt;
              let response = "there" in
              (* write something *)
              Incoming.C.write_string ic response 0 (String.length response);
              Incoming.C.flush ic
              >>= function
              | Error _ -> failwith "http_proxy_connect: flush returned error"
              | Ok ()   ->
                Lwt.wakeup_later forwarded_u ();
                Lwt.return_unit
          ) (fun server ->
            let json = Ezjsonm.from_string "{ }" in
            Slirp_stack.Slirp_stack.Debug.update_http_json json ()
            >>= function
            | Error (`Msg m) -> failwith ("Failed to enable HTTP proxy: " ^ m)
            | Ok () ->
              let open Slirp_stack in
              Client.TCPV4.create_connection (Client.tcpv4 stack.t) (primary_dns_ip, 3128)
              >>= function
              | Error _ ->
                Log.err (fun f -> f "Failed to connect to %s:3128" (Ipaddr.V4.to_string primary_dns_ip));
                failwith "test_proxy_connect: connect failed"
              | Ok flow ->
                Log.info (fun f -> f "Connected to %s:3128" (Ipaddr.V4.to_string primary_dns_ip));
                let oc = Outgoing.C.create flow in
                let request =
                  let connect = Cohttp.Request.make ~meth:`CONNECT (Uri.make ()) in
                  let resource = Fmt.strf "localhost:%d" server.Server.port in
                  { connect with Cohttp.Request.resource }
                in
                Outgoing.Request.write ~flush:true (fun _writer -> Lwt.return_unit) request oc
                >>= fun () ->
                Outgoing.Response.read oc
                >>= function
                | `Eof ->
                  failwith "test_proxy_connect: EOF on HTTP CONNECT"
                | `Invalid x ->
                  failwith ("test_proxy_connect: Invalid HTTP response: " ^ x)
                | `Ok res ->
                  if res.Cohttp.Response.status <> `OK
                  then failwith "test_proxy_connect: HTTP CONNECT failed";
                  let request = "hello" in
                  Outgoing.C.write_string oc request 0 (String.length request);
                  Outgoing.C.flush oc
                  >>= function
                  | Error _ -> failwith "http_proxy_connect: client flush returned error"
                  | Ok ()   ->
                    Outgoing.C.read_some ~len:5 oc
                    >>= function
                    | Ok `Eof -> failwith "http_proxy_connect: client read_some returned Eof"
                    | Error _ -> failwith "http_proxy_connect: client read_some returned Error"
                    | Ok (`Data buf) ->
                      let txt = Cstruct.to_string buf in
                      Alcotest.check Alcotest.string "message" "there" txt;
                      Lwt.pick [
                        (Host.Time.sleep_ns (Duration.of_sec 100) >|= fun () ->
                        `Timeout);
                        (forwarded >>= fun x -> Lwt.return (`Result x))
                      ]
          )
        >|= function
        | `Timeout  -> failwith "HTTP interception failed"
        | `Result x -> x
      )
    end

  let test_http_proxy_connect_fail () =
    Host.Main.run begin
      Slirp_stack.with_stack ~pcap:"test_http_proxy_connect_fail.pcap" (fun _ stack ->
        let open Slirp_stack in
        Client.TCPV4.create_connection (Client.tcpv4 stack.t) (primary_dns_ip, 3128)
        >>= function
        | Error _ ->
          Log.err (fun f -> f "Failed to connect to %s:3128" (Ipaddr.V4.to_string primary_dns_ip));
          failwith "test_proxy_connect_fail: connect failed"
        | Ok flow ->
          Log.info (fun f -> f "Connected to %s:3128" (Ipaddr.V4.to_string primary_dns_ip));
          let oc = Outgoing.C.create flow in
          let request =
            let connect = Cohttp.Request.make ~meth:`CONNECT (Uri.make ()) in
            (* Assume port 25 (SMTP) is free *)
            let resource = "localhost:25"  in
            { connect with Cohttp.Request.resource }
          in
          Outgoing.Request.write ~flush:true (fun _writer -> Lwt.return_unit) request oc
          >>= fun () ->
          Outgoing.Response.read oc
          >>= function
          | `Eof ->
            failwith "test_proxy_connect_fail: EOF on HTTP CONNECT"
          | `Invalid x ->
            failwith ("test_proxy_connect_fail: Invalid HTTP response: " ^ x)
          | `Ok res ->
            if res.Cohttp.Response.status = `OK
            then failwith "test_proxy_connect_fail: HTTP CONNECT succeeded unexpectedly";
            if res.Cohttp.Response.status <> `Service_unavailable
            then failwith "test_proxy_connect_fail: HTTP CONNECT failed with an unexpected code";
            Lwt.return_unit
        )
    end

  let test_http_proxy_get_dns () =
    Host.Main.run begin
      Slirp_stack.with_stack ~pcap:"test_http_proxy_get_dns.pcap" (fun _ stack ->
        let open Slirp_stack in
        Client.TCPV4.create_connection (Client.tcpv4 stack.t) (primary_dns_ip, 3128)
        >>= function
        | Error _ ->
          Log.err (fun f -> f "Failed to connect to %s:3128" (Ipaddr.V4.to_string primary_dns_ip));
          failwith "test_proxy_get_dns: connect failed"
        | Ok flow ->
          Log.info (fun f -> f "Connected to %s:3128" (Ipaddr.V4.to_string primary_dns_ip));
          let oc = Outgoing.C.create flow in
          let host = "does.not.exist.recoil.org" in
          let request = Cohttp.Request.make ~meth:`GET (Uri.make ~host ()) in
          Outgoing.Request.write ~flush:true (fun _writer -> Lwt.return_unit) request oc
          >>= fun () ->
          Outgoing.Response.read oc
          >>= function
          | `Eof ->
            failwith "test_proxy_get_dns: EOF on HTTP GET"
          | `Invalid x ->
            failwith ("test_proxy_get_dns: Invalid HTTP response: " ^ x)
          | `Ok res ->
            if res.Cohttp.Response.status = `OK
            then failwith "test_proxy_get_dns: HTTP GET to non-existent host succeeded unexpectedly";
            if res.Cohttp.Response.status <> `Service_unavailable
            then failwith "test_proxy_get_dns: HTTP GET to non-existent host failed with an unexpected code";
            Lwt.return_unit
        )
    end

  let test_http_proxy_get () =
    Host.Main.run begin
      Slirp_stack.with_stack ~pcap:"test_http_proxy_get.pcap" (fun _ stack ->
        let open Slirp_stack in
        Client.TCPV4.create_connection (Client.tcpv4 stack.t) (primary_dns_ip, 3128)
        >>= function
        | Error _ ->
          Log.err (fun f -> f "Failed to connect to %s:3128" (Ipaddr.V4.to_string primary_dns_ip));
          failwith "test_proxy_get: connect failed"
        | Ok flow ->
          Log.info (fun f -> f "Connected to %s:3128" (Ipaddr.V4.to_string primary_dns_ip));
          let oc = Outgoing.C.create flow in
          let host = "www.mobyproject.org" in
          let request = Cohttp.Request.make ~meth:`GET (Uri.make ~host ()) in
          Outgoing.Request.write ~flush:true (fun _writer -> Lwt.return_unit) request oc
          >>= fun () ->
          Outgoing.Response.read oc
          >>= function
          | `Eof ->
            failwith "test_proxy_get: EOF on HTTP GET"
          | `Invalid x ->
            failwith ("test_proxy_get: Invalid HTTP response: " ^ x)
          | `Ok res ->
            if res.Cohttp.Response.status <> `OK
            then failwith "test_proxy_get: HTTP GET failed unexpectedly";
            Lwt.return_unit
        )
    end

  let test_http_proxy_headers () =
    Host.Main.run begin
      let forwarded, forwarded_u = Lwt.task () in
      Slirp_stack.with_stack ~pcap:"test_http_proxy_headers.pcap" (fun _ stack ->
        with_server (fun flow ->
            let ic = Incoming.C.create flow in
            Incoming.Request.read ic >>= function
            | `Eof ->
              Log.err (fun f -> f "Failed to request");
              failwith "Failed to read request"
            | `Invalid x ->
              Log.err (fun f -> f "Failed to parse request: %s" x);
              failwith ("Failed to parse request: " ^ x)
            | `Ok req ->
              (* parse the response *)
              Lwt.wakeup_later forwarded_u req;
              Lwt.return_unit
          ) (fun server ->
            let host = "127.0.0.1" in
            let port = server.Server.port in
            let open Slirp_stack in
            Client.TCPV4.create_connection (Client.tcpv4 stack.t) (primary_dns_ip, 3128)
            >>= function
            | Error _ ->
              Log.err (fun f -> f "Failed to connect to %s:3128" (Ipaddr.V4.to_string primary_dns_ip));
              failwith "test_proxy_get: connect failed"
            | Ok flow ->
              Log.info (fun f -> f "Connected to %s:3128" (Ipaddr.V4.to_string primary_dns_ip));
              let oc = Outgoing.C.create flow in
              let request = Cohttp.Request.make ~meth:`GET (Uri.make ~host ~port ()) in
              Outgoing.Request.write ~flush:true (fun _writer -> Lwt.return_unit) request oc
              >>= fun () ->
              forwarded
              >>= fun result ->
              Log.info (fun f ->
              f "original was: %s"
                (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t request)));
              Log.info (fun f ->
                  f "proxied  was: %s"
                    (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t result)));
              Alcotest.check Alcotest.string "method"
                (Cohttp.Code.string_of_method request.Cohttp.Request.meth)
                (Cohttp.Code.string_of_method result.Cohttp.Request.meth);
              Alcotest.check Alcotest.string "version"
                (Cohttp.Code.string_of_version request.Cohttp.Request.version)
                (Cohttp.Code.string_of_version result.Cohttp.Request.version);
              Alcotest.check Alcotest.(option string) "URI.host"
                (Cohttp.Request.uri request |> Uri.host)
                (Cohttp.Request.uri result |> Uri.host);
              Alcotest.check Alcotest.(list string) "host headers"
                (Cohttp.Header.to_list request.Cohttp.Request.headers |> List.filter (fun (x, _) -> x = "host") |> List.map snd)
                (Cohttp.Header.to_list result.Cohttp.Request.headers |> List.filter (fun (x, _) -> x = "host") |> List.map snd);
              Lwt.return_unit
            )
        )
    end

  let test_connection_close explicit_close () =
    let body = "Hello\n" in
    Host.Main.run begin
    Slirp_stack.with_stack ~pcap:"test_connection_close.pcap" (fun _ stack ->
        with_server (fun flow ->
            let ic = Incoming.C.create flow in
            Incoming.Request.read ic >>= function
            | `Eof ->
              Log.err (fun f -> f "Failed to request");
              failwith "Failed to read request"
            | `Invalid x ->
              Log.err (fun f -> f "Failed to parse request: %s" x);
              failwith ("Failed to parse request: " ^ x)
            | `Ok _ ->
              let response =
                if explicit_close
                then "HTTP/1.0 200 OK\r\nConnection:close\r\n\r\n" ^ body
                else "HTTP/1.0 200 OK\r\n\r\n" ^ body in
              Incoming.C.write_string ic response 0 (String.length response);
              Incoming.C.flush ic
              >>= function
              | Error _ -> failwith "test_connection_close: flush returned error"
              | Ok ()   ->
                (* Connection will be closed here *)
                Lwt.return_unit
          ) (fun origin_server ->
            let host = "127.0.0.1" in
            let port = origin_server.Server.port in
            Log.info (fun f -> f "HTTP origin server is on %s:%d" host port);
            let open Slirp_stack in
            (* Disable the proxy so the builtin proxy will have to fetch from the origin server *)
            Slirp_stack.Debug.update_http ()
            >>= function
            | Error (`Msg m) -> failwith ("Failed to disable HTTP proxy: " ^ m)
            | Ok () ->
              (* Connect to the builtin HTTP Proxy *)
              Client.TCPV4.create_connection (Client.tcpv4 stack.t) (primary_dns_ip, 3128)
              >>= function
              | Error _ ->
                Log.err (fun f -> f "Failed to connect to %s:3128" (Ipaddr.V4.to_string primary_dns_ip));
                failwith "test_connection_close: connect failed"
              | Ok flow ->
                Log.info (fun f -> f "Connected to %a:3128" Ipaddr.V4.pp primary_dns_ip);
                let oc = Outgoing.C.create flow in
                let request =
                  let uri = Uri.make ~scheme:"http" ~host:"localhost" ~port () in
                  Cohttp.Request.make ~meth:`GET uri
                in
                Outgoing.Request.write ~flush:true (fun _writer -> Lwt.return_unit) request oc
                >>= fun () ->
                let response =
                  Outgoing.Response.read oc
                  >>= function
                  | `Eof ->
                    failwith "test_connection_close: EOF on HTTP GET"
                  | `Invalid x ->
                    failwith ("test_connection_close: Invalid HTTP response: " ^ x)
                  | `Ok res ->
                    if res.Cohttp.Response.status <> `OK
                    then failwith "test_connection_close: HTTP GET failed";
                    let reader = Outgoing.Response.make_body_reader res oc in
                    let buf = Buffer.create 100 in
                    let rec loop () =
                      let open Cohttp.Transfer in
                      Outgoing.Response.read_body_chunk reader >>= function
                      | Done          -> Lwt.return_unit
                      | Final_chunk x -> Buffer.add_string buf x; Lwt.return_unit
                      | Chunk x       ->
                        Buffer.add_string buf x;
                        loop () in
                    loop ()
                    >>= fun () ->
                    let txt = Buffer.contents buf in
                    Alcotest.check Alcotest.string "body" body txt;
                    Lwt.return (`Result ()) in
                  Lwt.pick [
                    (Host.Time.sleep_ns (Duration.of_sec 100) >|= fun () ->
                    `Timeout);
                    response;
                  ]
          )
        >|= function
        | `Timeout  -> failwith "HTTP interception failed"
        | `Result () -> ()
      )
    end

  let test_http_proxy_localhost host_or_ip () =
    Host.Main.run begin
      let forwarded, forwarded_u = Lwt.task () in
      Slirp_stack.with_stack ~pcap:"test_http_proxy_localhost.pcap" (fun _ stack ->
        with_server (fun flow ->
            let ic = Incoming.C.create flow in
            Incoming.Request.read ic >>= function
            | `Eof ->
              Log.err (fun f -> f "Failed to request");
              failwith "Failed to read request"
            | `Invalid x ->
              Log.err (fun f -> f "Failed to parse request: %s" x);
              failwith ("Failed to parse request: " ^ x)
            | `Ok req ->
              (* parse the response *)
              Lwt.wakeup_later forwarded_u req;
              Lwt.return_unit
          ) (fun server ->
            let host = host_or_ip in
            let port = server.Server.port in
            let open Slirp_stack in
            Client.TCPV4.create_connection (Client.tcpv4 stack.t) (primary_dns_ip, 3128)
            >>= function
            | Error _ ->
              Log.err (fun f -> f "Failed to connect to %s:3128" (Ipaddr.V4.to_string primary_dns_ip));
              failwith "test_proxy_get: connect failed"
            | Ok flow ->
              Log.info (fun f -> f "Connected to %s:3128" (Ipaddr.V4.to_string primary_dns_ip));
              let oc = Outgoing.C.create flow in
              let request = Cohttp.Request.make ~meth:`GET (Uri.make ~host ~port ()) in
              Outgoing.Request.write ~flush:true (fun _writer -> Lwt.return_unit) request oc
              >>= fun () ->
              forwarded
              >>= fun result ->
              Log.info (fun f ->
              f "original was: %s"
                (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t request)));
              Log.info (fun f ->
                  f "proxied  was: %s"
                    (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t result)));
              Alcotest.check Alcotest.string "method"
                (Cohttp.Code.string_of_method request.Cohttp.Request.meth)
                (Cohttp.Code.string_of_method result.Cohttp.Request.meth);
              Alcotest.check Alcotest.string "version"
                (Cohttp.Code.string_of_version request.Cohttp.Request.version)
                (Cohttp.Code.string_of_version result.Cohttp.Request.version);
              Alcotest.check Alcotest.(option string) "URI.host"
                (Cohttp.Request.uri request |> Uri.host)
                (Cohttp.Request.uri result |> Uri.host);
              Alcotest.check Alcotest.(list string) "host headers"
                (Cohttp.Header.to_list request.Cohttp.Request.headers |> List.filter (fun (x, _) -> x = "host") |> List.map snd)
                (Cohttp.Header.to_list result.Cohttp.Request.headers |> List.filter (fun (x, _) -> x = "host") |> List.map snd);
              Lwt.return_unit
            )
        )
    end


  let test_http_proxy_head () =
    Host.Main.run begin
      Slirp_stack.with_stack ~pcap:"test_http_proxy_head.pcap" (fun _ stack ->
        let open Slirp_stack in
        Client.TCPV4.create_connection (Client.tcpv4 stack.t) (primary_dns_ip, 3128)
        >>= function
        | Error _ ->
          Log.err (fun f -> f "Failed to connect to %s:3128" (Ipaddr.V4.to_string primary_dns_ip));
          failwith "test_proxy_head: connect failed"
        | Ok flow ->
          Log.info (fun f -> f "Connected to %s:3128" (Ipaddr.V4.to_string primary_dns_ip));
          let oc = Outgoing.C.create flow in
          let host = "www.mobyproject.org" in
          let request = Cohttp.Request.make ~meth:`HEAD (Uri.make ~host ()) in
          Outgoing.Request.write ~flush:true (fun _writer -> Lwt.return_unit) request oc
          >>= fun () ->
          Outgoing.Response.read oc
          >>= function
          | `Eof ->
            failwith "test_proxy_head: EOF on HTTP HEAD"
          | `Invalid x ->
            failwith ("test_proxy_head: Invalid HTTP response: " ^ x)
          | `Ok res ->
            if res.Cohttp.Response.status <> `OK
            then failwith "test_proxy_head: HTTP HEAD failed unexpectedly";
            (* Now try another request to see if the channel still works *)
            let request = Cohttp.Request.make ~meth:`GET (Uri.make ~host ()) in
            Outgoing.Request.write ~flush:true (fun _writer -> Lwt.return_unit) request oc
            >>= fun () ->
            let t =
              Outgoing.Response.read oc
              >>= function
              | `Eof ->
                failwith "test_proxy_head: EOF on HTTP GET after HEAD"
              | `Invalid x ->
                failwith ("test_proxy_head: Invalid HTTP response: " ^ x)
              | `Ok res ->
                if res.Cohttp.Response.status <> `OK
                then failwith "test_proxy_head: HTTP GET after HEAD failed unexpectedly";
                Lwt.return `Ok in
            Lwt.pick [
              (Host.Time.sleep_ns (Duration.of_sec 100) >|= fun () -> `Timeout);
              t
            ] >>= function
            | `Timeout -> failwith "test_proxy_head timed out"
            | `Ok -> Lwt.return_unit
        )
    end

  let test_transparent_http_proxy_exclude () =
    Host.Main.run begin
      let forwarded, forwarded_u = Lwt.task () in
      Slirp_stack.with_stack ~pcap:"test_transparent_http_proxy_exclude.pcap" (fun _ stack ->
        (* Start a web server (not a proxy) *)
        with_server (fun flow ->
          let ic = Incoming.C.create flow in
          Incoming.Request.read ic >>= function
          | `Eof ->
            Log.err (fun f -> f "Failed to request");
            failwith "Failed to read request"
          | `Invalid x ->
            Log.err (fun f -> f "Failed to parse request: %s" x);
            failwith ("Failed to parse request: " ^ x)
          | `Ok req ->
            (* parse the response *)
            Lwt.wakeup_later forwarded_u req;
            Lwt.return_unit
        ) (fun server ->
          let host = "127.0.0.1" in
          let port = server.Server.port in
          Log.info (fun f -> f "HTTP server is on %s:%d" host port);
          let open Slirp_stack in
          Slirp_stack.Debug.update_http
            ~exclude:"localhost"
            ~http:(Printf.sprintf "http://localhost:%d" (port + 1))
            ~transparent_http_ports:[port]
            ()
          >>= function
          | Error (`Msg m) -> failwith ("Failed to enable HTTP proxy: " ^ m)
          | Ok () ->
            (* Create a regular HTTP connection, this should be caught by the transparent
               proxy *)
            Client.TCPV4.create_connection (Client.tcpv4 stack.t) (Ipaddr.V4.of_string_exn host, port)
            >>= function
            | Error _ ->
              Log.err (fun f -> f "Failed to connect to %s:%d" host port);
              failwith "test_transparent_http_proxy_exclude: connect failed"
            | Ok flow ->
              Log.info (fun f -> f "Connected to %s:%d" host port);
              let oc = Outgoing.C.create flow in
              let host = "localhost" in
              (* Add Host: localhost so the request should bypass the proxy *)
              let headers =
                Cohttp.Header.add (Cohttp.Header.init ()) "Host" ("localhost:" ^ (string_of_int port))
              in
              let request = Cohttp.Request.make ~meth:`GET ~headers (Uri.make ~host ()) in
              Outgoing.Request.write ~flush:true (fun _writer -> Lwt.return_unit) request oc
              >>= fun () ->
              Lwt.pick [
                  (Host.Time.sleep_ns (Duration.of_sec 100) >|= fun () -> `Timeout);
                  forwarded >|= fun request ->
                  Log.info (fun f ->
                    f "Successfully received: %s"
                      (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t request)));
                    `Ok
                ] >>= function
              | `Timeout -> failwith "test_transparent_http_proxy_exclude timed out"
              | `Ok -> Lwt.return_unit
        )
      )
    end


let proxy_urls = [
  "http://127.0.0.1";
  "http://user:password@127.0.0.1";
  "http://localhost";
] @ (List.map (fun name ->
  Printf.sprintf "http://%s" (Dns.Name.to_string name)
) Slirp_stack.names_for_localhost)

let tests = [

  "HTTP: interception",
  [ "", `Quick, test_interception "http://127.0.0.1" ];

  "HTTP proxy: CONNECT",
  [ "check that HTTP CONNECT requests through the proxy", `Quick, test_http_proxy_connect ];

  "HTTP proxy: CONNECT fails",
  [ "check that HTTP CONNECT fails if the port is not found", `Quick, test_http_proxy_connect_fail ];

  "HTTP proxy: GET to bad host",
  [ "check that HTTP GET fails if the DNS doesn't resolve", `Quick, test_http_proxy_get_dns ];

  "HTTP proxy: GET to good host",
  [ "check that HTTP GET succeeds normally", `Quick, test_http_proxy_get ];

  "HTTP proxy: GET has good headers",
  [ "check that HTTP GET headers are correct", `Quick, test_http_proxy_headers ];

  "HTTP proxy: GET to localhost works",
  [ "check that HTTP GET to localhost via IP", `Quick, test_http_proxy_localhost (Ipaddr.V4.to_string Slirp_stack.localhost_ip) ];

  "HTTP proxy: transparent proxy respects excludes",
  [ "check that the transparent proxy will inspect and respect the Host: header", `Quick, test_transparent_http_proxy_exclude ];

  "HTTP proxy: respect connection: close",
  [ "check that the transparent proxy will respect connection: close headers from origin servers", `Quick, test_connection_close true ];

  "HTTP proxy: respect HTTP/1.0 implicit connection: close",
  [ "check that the transparent proxy will respect HTTP/1.0 implicit connection: close headers from origin servers", `Quick, test_connection_close true ];

] @ (List.map (fun name ->
    "HTTP proxy: GET to localhost",
    [ "check that HTTP GET to localhost via hostname", `Quick, test_http_proxy_localhost (Dns.Name.to_string name) ]
  ) Slirp_stack.names_for_localhost
) @ (List.concat @@ List.map (fun proxy -> [

  "HTTP: URI",
  [ "check that relative URIs are rewritten", `Quick, test_uri_relative proxy ];

  "HTTP: absolute URI",
  [ "check that absolute URIs from proxies are preserved", `Quick, test_uri_absolute proxy ];

  "HTTP: custom header",
  ["check that custom headers are preserved", `Quick, test_x_header_preserved proxy ];

  "HTTP: user-agent",
  [ "check that user-agent is preserved", `Quick, test_user_agent_preserved proxy ];

  "HTTP: authorization",
  [ "check that authorization is preserved", `Quick, test_authorization_preserved proxy ];

  "HTTP: proxy-authorization",
  [ "check that proxy-authorization is present when proxy = " ^ proxy, `Quick, test_proxy_authorization proxy ];

  "HTTP: CONNECT tunnel though " ^ proxy,
  [ "check that HTTP CONNECT tunnelling works for HTTPS with proxy " ^ proxy, `Quick, test_http_connect_tunnel (Uri.of_string proxy) ];

  "HTTP: CONNECT forwarded to " ^ proxy,
  [ "check that HTTP CONNECT are forwarded correctly to proxy " ^ proxy, `Quick, test_http_connect_forward (Uri.of_string proxy) ];

  ]) proxy_urls) @ [
  "HTTP: HEAD",
  [ "check that HTTP HEAD doesn't block the connection", `Quick, test_http_proxy_head ];
]
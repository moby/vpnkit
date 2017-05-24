open Lwt.Infix

let src =
  let src = Logs.Src.create "http" ~doc:"Test the HTTP proxy" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Make(Host: Sig.HOST) = struct

  module Slirp_stack = Slirp_stack.Make(Host)

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
    module C = Channel.Make(Slirp_stack.Client.TCPV4)
    module IO = Cohttp_mirage_io.Make(C)
    module Request = Cohttp.Request.Make(IO)
    module Response = Cohttp.Response.Make(IO)
  end
  module Incoming = struct
    module C = Channel.Make(Host.Sockets.Stream.Tcp)
    module IO = Cohttp_mirage_io.Make(C)
    module Request = Cohttp.Request.Make(IO)
    module Response = Cohttp.Response.Make(IO)
  end

  let send_http_request stack ip request =
    let open Slirp_stack in
    Client.TCPV4.create_connection (Client.tcpv4 stack) (ip, 80)
    >>= function
    | `Ok flow ->
      Log.info (fun f -> f "Connected to %s:80" (Ipaddr.V4.to_string ip));
      let oc = Outgoing.C.create flow in
      Outgoing.Request.write ~flush:true (fun _writer -> Lwt.return_unit) request oc
    | `Error _ ->
      Log.err (fun f -> f "Failed to connect to %s:80" (Ipaddr.V4.to_string ip));
        failwith "http_fetch"

  let intercept request =
    let forwarded, forwarded_u = Lwt.task () in
    Slirp_stack.with_stack
      (fun _ stack ->
        with_server
          (fun flow ->
            let ic = Incoming.C.create flow in
            Incoming.Request.read ic
            >>= function
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
            let json = Ezjsonm.from_string (" { \"http\": \"127.0.0.1:" ^ (string_of_int server.Server.port) ^ "\" }") in
            Slirp_stack.Slirp_stack.Debug.update_http_json json ()
            >>= function
            | Error (`Msg m) -> failwith ("Failed to enable HTTP proxy: " ^ m)
            | Ok () ->
              send_http_request stack (Ipaddr.V4.of_string_exn "127.0.0.1") request
              >>= fun () ->
              Lwt.pick [ (Host.Time.sleep 100. >>= fun () -> Lwt.return `Timeout); (forwarded >>= fun x -> Lwt.return (`Result x)) ]
          )
        >>= function
        | `Timeout ->
          failwith "HTTP interception failed"
        | `Result x ->
          Lwt.return x
      )

  (* Test that HTTP interception works at all *)
  let test_interception () =
    Host.Main.run begin
      let request = Cohttp.Request.make (Uri.make ~scheme:"http" ~host:"dave.recoil.org" ~path:"/" ()) in
      intercept request
      >>= fun result ->
      Log.info (fun f -> f "original was: %s" (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t request)));
      Log.info (fun f -> f "proxied  was: %s" (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t result)));
      Alcotest.check Alcotest.string "method" (Cohttp.Code.string_of_method request.Cohttp.Request.meth) (Cohttp.Code.string_of_method result.Cohttp.Request.meth);
      Alcotest.check Alcotest.string "version" (Cohttp.Code.string_of_version request.Cohttp.Request.version) (Cohttp.Code.string_of_version result.Cohttp.Request.version);
      Lwt.return ()
    end

  (* Test that the URI becomes absolute *)
  let test_uri_absolute () =
    Host.Main.run begin
      let request = Cohttp.Request.make (Uri.make ~scheme:"http" ~host:"dave.recoil.org" ~path:"/" ()) in
      intercept request
      >>= fun result ->
      Log.info (fun f -> f "original was: %s" (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t request)));
      Log.info (fun f -> f "proxied  was: %s" (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t result)));
      let uri = Uri.of_string result.Cohttp.Request.resource in
      Alcotest.check Alcotest.(option string) "scheme" (Some "http") (Uri.scheme uri);
      Lwt.return ()
    end

  (* Verify that a custom X- header is preserved *)
  let test_x_header_preserved () =
    Host.Main.run begin
      let headers = Cohttp.Header.add (Cohttp.Header.init ()) "X-dave-is-cool" "true" in
      let request = Cohttp.Request.make ~headers (Uri.make ~scheme:"http" ~host:"dave.recoil.org" ~path:"/" ()) in
      intercept request
      >>= fun result ->
      Log.info (fun f -> f "original was: %s" (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t request)));
      Log.info (fun f -> f "proxied  was: %s" (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t result)));
      Alcotest.check Alcotest.(option string) "X-header" (Some "true") (Cohttp.Header.get result.Cohttp.Request.headers "X-dave-is-cool");
      Lwt.return ()
    end

  (* Verify that the user-agent is preserved. In particular we don't want our
     http library to leak here. *)
  let test_user_agent_preserved () =
    Host.Main.run begin
      let headers = Cohttp.Header.add (Cohttp.Header.init ()) "user-agent" "whatever" in
      let request = Cohttp.Request.make ~headers (Uri.make ~scheme:"http" ~host:"dave.recoil.org" ~path:"/" ()) in
      intercept request
      >>= fun result ->
      Log.info (fun f -> f "original was: %s" (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t request)));
      Log.info (fun f -> f "proxied  was: %s" (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t result)));
      Alcotest.check Alcotest.(option string) "user-agent" (Some "whatever") (Cohttp.Header.get result.Cohttp.Request.headers "user-agent");
      Lwt.return ()
    end

  let test_http_connect () =
    let test_dst_ip = Ipaddr.V4.of_string_exn "1.2.3.4" in
    Host.Main.run begin
      Slirp_stack.with_stack
        (fun _ stack ->
          with_server
            (fun flow ->
              let ic = Incoming.C.create flow in
              Incoming.Request.read ic
              >>= function
              | `Eof ->
                Log.err (fun f -> f "Failed to request");
                failwith "Failed to read request"
              | `Invalid x ->
                Log.err (fun f -> f "Failed to parse request: %s" x);
                failwith ("Failed to parse request: " ^ x)
              | `Ok req ->
                Log.info (fun f -> f "received: %s" (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t req)));
                Alcotest.check Alcotest.string "method" (Cohttp.Code.string_of_method `CONNECT) (Cohttp.Code.string_of_method req.Cohttp.Request.meth);
                let uri = Cohttp.Request.uri req in
                Alcotest.check Alcotest.(option string) "host" (Some (Ipaddr.V4.to_string test_dst_ip)) (Uri.host uri);
                Alcotest.check Alcotest.(option int) "port" (Some 443) (Uri.port uri);
                (* Unfortunately cohttp always adds transfer-encoding: chunked
                   so we write the header ourselves *)
                Incoming.C.write_line ic "HTTP/1.0 200 OK\r";
                Incoming.C.write_line ic "\r";
                Incoming.C.flush ic
                >>= fun () ->
                Incoming.C.write_line ic "hello";
                Incoming.C.flush ic
            ) (fun server ->
              Slirp_stack.Slirp_stack.Debug.update_http ~https:("127.0.0.1:" ^ (string_of_int server.Server.port)) ()
              >>= function
              | Error (`Msg m) -> failwith ("Failed to enable HTTP proxy: " ^ m)
              | Ok () ->
                let open Slirp_stack in
                begin Client.TCPV4.create_connection (Client.tcpv4 stack) (test_dst_ip, 443)
                >>= function
                | `Error _ ->
                  Log.err (fun f -> f "TCPV4.create_connection %s:443 failed" (Ipaddr.V4.to_string test_dst_ip));
                  failwith "TCPV4.create_connection"
                | `Ok flow ->
                  let ic = Outgoing.C.create flow in
                  Outgoing.C.read_some ~len:5 ic
                  >>= fun buf ->
                  let txt = Cstruct.to_string buf in
                  Alcotest.check Alcotest.string "message" "hello" txt;
                  Lwt.return_unit
                end
            )
        )
    end

  let suite = [
    "interception", `Quick, test_interception;
    "URI", `Quick, test_uri_absolute;
    "custom_header", `Quick, test_x_header_preserved;
    "user_agent", `Quick, test_user_agent_preserved;
    "CONNECT", `Quick, test_http_connect;
  ]

end

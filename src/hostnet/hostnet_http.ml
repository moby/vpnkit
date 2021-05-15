open Lwt.Infix
open Astring

let src =
  let src = Logs.Src.create "http" ~doc:"HTTP proxy" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let errorf fmt = Fmt.kstrf (fun e -> Lwt.return (Error (`Msg e))) fmt

module Exclude = struct

  module One = struct
    module Element = struct
      (* One element of a DNS name *)
      type t = Any | String of string

      let of_string = function
      | "*" | "" -> Any
      | x -> String x

      let to_string = function
      | Any -> "*"
      | String x -> x

      let matches x = function
      | Any -> true
      | String y -> x = y
    end

    type t =
      | Subdomain of Element.t list
      | CIDR of Ipaddr.V4.Prefix.t
      | IP of Ipaddr.V4.t

    let of_string s =
      match Ipaddr.V4.Prefix.of_string s with
      | Error _ ->
        begin match Ipaddr.V4.of_string s with
        | Error _ ->
          let bits = Astring.String.cuts ~sep:"." s in
          Subdomain (List.map Element.of_string bits)
        | Ok ip -> IP ip
        end
      | Ok prefix -> CIDR prefix

    let to_string = function
    | Subdomain x ->
      "Subdomain " ^ String.concat ~sep:"." @@ List.map Element.to_string x
    | CIDR prefix -> "CIDR " ^ Ipaddr.V4.Prefix.to_string prefix
    | IP ip -> "IP " ^ Ipaddr.V4.to_string ip

    let matches_ip ip = function
    | CIDR prefix -> Ipaddr.V4.Prefix.mem ip prefix
    | IP ip' -> Ipaddr.V4.compare ip ip' = 0
    | _ -> false

    let matches_host host = function
    | CIDR _ | IP _ -> false
    | Subdomain domains ->
      let bits = Astring.String.cuts ~sep:"." host in
      (* does 'bits' match 'domains' *)
      let rec loop bits domains = match bits, domains with
      | _, [] -> true
      | [], _ :: _ -> false
      | b :: bs, d :: ds -> Element.matches b d && loop bs ds in
      loop (List.rev bits) (List.rev domains)

    let matches thing exclude =
      match Ipaddr.V4.of_string thing with
      | Error _ -> matches_host thing exclude
      | Ok ip -> matches_ip ip exclude
  end

  type t = One.t list

  let none = []

  let of_string s =
    let open Astring in
    (* Accept either space or comma-separated ignoring whitespace *)
    let parts =
      String.fields ~empty:false
        ~is_sep:(fun c -> c = ',' || Char.Ascii.is_white c) s
    in
    List.map One.of_string parts

  let to_string t = String.concat ~sep:" " @@ (List.map One.to_string t)

  let matches thing t =
    List.fold_left (||) false (List.map (One.matches thing) t)

end

let error_html title body =
  Printf.sprintf
"<html><head>
<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">
<title>%s</title>
</head><body>
%s
<br>
<p>Server is <a href=\"https://github.com/moby/vpnkit\">moby/vpnkit</a></p>
</body>
</html>
" title body

module Make
    (Ip: Mirage_protocols.IPV4)
    (Udp: Mirage_protocols.UDPV4)
    (Tcp:Mirage_flow_combinators.SHUTDOWNABLE)
    (Socket: Sig.SOCKETS)
    (Dns_resolver: Sig.DNS)
= struct

  type proxy = Uri.t

  let string_of_proxy = Uri.to_string

  (* Support both http://user:pass@host:port/ and host:port *)
  let proxy_of_string x =
    (* Is it a URL? *)
    let uri = Uri.of_string x in
    match Uri.host uri, Uri.port uri with
    | Some _, Some _ -> Some uri
    | _, _ ->
      begin match String.cuts ~sep:":" x with
      | [] ->
        Log.err (fun f -> f "Failed to parse HTTP(S) proxy as URI or host:port: %s" x);
        None
      | [host; port] ->
        begin
          try
            let port = int_of_string port in
            Some (Uri.make ~scheme:"http" ~host ~port ())
          with Failure _ ->
            Log.err (fun f -> f "Failed to parse HTTP(S) proxy as URI or host:port: %s" x);
            None
        end
      | _ ->
        Log.err (fun f -> f "Failed to parse HTTP(S) proxy as URI or host:port: %s" x);
        None
      end

  let string_of_address (ip, port) = Fmt.strf "%s:%d" (Ipaddr.to_string ip) port

  type t = {
    http: proxy option;
    https: proxy option;
    exclude: Exclude.t;
    transparent_http_ports: int list;
    transparent_https_ports: int list;
  }

  let resolve_ip name_or_ip =
    match Ipaddr.of_string name_or_ip with
    | Error _ ->
      let open Dns.Packet in
      let question =
        make_question ~q_class:Q_IN Q_A (Dns.Name.of_string name_or_ip)
      in
      Dns_resolver.resolve question
      >>= fun rrs ->
      (* Any IN record will do (NB it might be a CNAME) *)
      let rec find_ip = function
        | { cls = RR_IN; rdata = A ipv4; _ } :: _ ->
          Lwt.return (Ok (Ipaddr.V4 ipv4))
        | _ :: rest -> find_ip rest
        | [] -> errorf "Failed to lookup host: %s" name_or_ip in
      find_ip rrs
    | Ok x -> Lwt.return (Ok x)

  let to_json t =
    let open Ezjsonm in
    let http = match t.http with
    | None   -> []
    | Some x -> [ "http",  string @@ string_of_proxy x ]
    in
    let https = match t.https with
    | None   -> []
    | Some x -> [ "https", string @@ string_of_proxy x ]
    in
    let exclude = [ "exclude", string @@ Exclude.to_string t.exclude ] in
    let transparent_http_ports = [ "transparent_http_ports", list int t.transparent_http_ports ] in
    let transparent_https_ports = [ "transparent_https_ports", list int t.transparent_https_ports ] in
    dict (http @ https @ exclude @ transparent_http_ports @ transparent_https_ports)

  let of_json j =
    let open Ezjsonm in
    let http =
      try Some (get_string @@ find j [ "http" ])
      with Not_found -> None
    in
    let https =
      try Some (get_string @@ find j [ "https" ])
      with Not_found -> None
    in
    let exclude =
      try Exclude.of_string @@ get_string @@ find j [ "exclude" ]
      with Not_found -> Exclude.none
    in
    let transparent_http_ports =
      try get_list get_int @@ find j [ "transparent_http_ports" ]
      with Not_found -> [ 80 ] in
    let transparent_https_ports =
      try get_list get_int @@ find j [ "transparent_https_ports" ]
      with Not_found -> [ 443 ] in
    let http = match http with None -> None | Some x -> proxy_of_string x in
    let https = match https with None -> None | Some x -> proxy_of_string x in
    Lwt.return (Ok { http; https; exclude; transparent_http_ports; transparent_https_ports })

  let to_string t = Ezjsonm.to_string ~minify:false @@ to_json t

  let create ?http ?https ?exclude ?(transparent_http_ports=[ 80 ]) ?(transparent_https_ports=[ 443 ]) () =
    let http = match http with None -> None | Some x -> proxy_of_string x in
    let https = match https with None -> None | Some x -> proxy_of_string x in
    let exclude = match exclude with None -> [] | Some x -> Exclude.of_string x in
    let t = { http; https; exclude; transparent_http_ports; transparent_https_ports } in
    Log.info (fun f -> f "HTTP proxy settings changed to: %s" (to_string t));
    Lwt.return (Ok t)

  module Incoming = struct
    module C = Mirage_channel.Make(Tcp)
    module IO = Cohttp_mirage_io.Make(C)
    module Request = Cohttp.Request.Make(IO)
    module Response = Cohttp.Response.Make(IO)
  end
  module Outgoing = struct
    module C = Mirage_channel.Make(Socket.Stream.Tcp)
    module IO = Cohttp_mirage_io.Make(C)
    module Request = Cohttp.Request.Make(IO)
    module Response = Cohttp.Response.Make(IO)
  end

  (* Since we've already layered a channel on top, we can't use the Mirage_flow.proxy
     since it would miss the contents already buffered. Therefore we write out own
     channel-level proxy here: *)
  let proxy_bytes ~incoming ~outgoing ~flow ~remote =
    (* forward outgoing to ingoing *)
    let a_t flow ~incoming ~outgoing =
      let warn pp e =
        Log.warn (fun f -> f "Unexpected exeption %a in proxy" pp e);
      in
      let rec loop () =
        Lwt.catch
          (fun () ->
            Outgoing.C.read_some outgoing >>= function
              | Ok `Eof        -> Lwt.return false
              | Error e        -> warn Outgoing.C.pp_error e; Lwt.return false
              | Ok (`Data buf) ->
                Incoming.C.write_buffer incoming buf;
                Incoming.C.flush incoming >|= function
                | Ok ()         -> true
                | Error `Closed -> false
                | Error e       -> warn Incoming.C.pp_write_error e; false
          ) (fun e ->
            Log.warn (fun f -> f "a_t: caught unexpected exception: %s" (Printexc.to_string e));
            Lwt.return false
          )
        >>= fun continue ->
        if continue then loop () else Tcp.close flow
      in
      loop () in

    (* forward ingoing to outgoing *)
    let b_t remote ~incoming ~outgoing =
      let warn pp e =
        Log.warn (fun f -> f "Unexpected exeption %a in proxy" pp e);
      in
      let rec loop () =
        Lwt.catch
          (fun () ->
            Incoming.C.read_some incoming >>= function
              | Ok `Eof        -> Lwt.return false
              | Error e        -> warn Incoming.C.pp_error e; Lwt.return false
              | Ok (`Data buf) ->
                Outgoing.C.write_buffer outgoing buf;
                Outgoing.C.flush outgoing >|= function
                | Ok ()         -> true
                | Error `Closed -> false
                | Error e       -> warn Outgoing.C.pp_write_error e; false
          ) (fun e ->
            Log.warn (fun f -> f "b_t: caught unexpected exception: %s" (Printexc.to_string e));
            Lwt.return false
          )
        >>= fun continue ->
        if continue then loop () else Socket.Stream.Tcp.shutdown_write remote
      in
      loop () in
    Lwt.join [
      a_t flow ~incoming ~outgoing;
      b_t remote ~incoming ~outgoing
    ]

  let rec proxy_body_request_exn ~reader ~writer =
    let open Cohttp.Transfer in
    Incoming.Request.read_body_chunk reader >>= function
    | Done          -> Lwt.return_unit
    | Final_chunk x -> Outgoing.Request.write_body writer x
    | Chunk x       ->
      Outgoing.Request.write_body writer x >>= fun () ->
      proxy_body_request_exn ~reader ~writer

  let rec proxy_body_response_exn ~reader ~writer =
    let open Cohttp.Transfer in
    Outgoing.Response.read_body_chunk reader  >>= function
    | Done          -> Lwt.return_unit
    | Final_chunk x -> Incoming.Response.write_body writer x
    | Chunk x       ->
      Incoming.Response.write_body writer x >>= fun () ->
      proxy_body_response_exn ~reader ~writer

  (* Take a request and a pair (incoming, outgoing) of channels, send
     the request to the outgoing channel and then proxy back any response.
     This function can raise exceptions because Cohttp can raise exceptions. *)
  let proxy_request ~description ~incoming ~outgoing ~flow ~remote ~req =
    (* Cohttp can fail promises so we catch them here *)
    Lwt.catch
      (fun () ->
        let reader = Incoming.Request.make_body_reader req incoming in
        Log.info (fun f -> f "Outgoing.Request.write");
        Outgoing.Request.write ~flush:true (fun writer ->
            match Incoming.Request.has_body req with
            | `Yes     -> proxy_body_request_exn ~reader ~writer
            | `No      -> Lwt.return_unit
            | `Unknown ->
              Log.warn (fun f ->
                  f "Request.has_body returned `Unknown: not sure what \
                      to do");
              Lwt.return_unit
          ) req outgoing
        >>= fun () ->
        Log.info (fun f -> f "Outgoing.Response.read");

        Outgoing.Response.read outgoing >>= function
        | `Eof ->
          Log.warn (fun f -> f "%s: EOF" (description false));
          Lwt.return false
        | `Invalid x ->
          Log.warn (fun f ->
              f "%s: Failed to parse HTTP response: %s"
                (description false) x);
          Lwt.return false
        | `Ok res ->
          Log.info (fun f ->
              f "%s: %s %s"
                (description false)
                (Cohttp.Code.string_of_version res.Cohttp.Response.version)
                (Cohttp.Code.string_of_status res.Cohttp.Response.status));
          Log.debug (fun f ->
              f "%s" (Sexplib.Sexp.to_string_hum
                        (Cohttp.Response.sexp_of_t res)));
          let res_headers = res.Cohttp.Response.headers in
          let connection_close =
            (* HTTP 1.0 defaults to Connection: close *)
            match res.Cohttp.Response.version, Cohttp.Header.get res_headers "connection" with
            | _, Some "keep-alive" -> false
            | _, Some "close" -> true
            | `HTTP_1_0, _ -> true
            | _, _ -> false in
          match Cohttp.Request.meth req, Cohttp.Response.status res with
          | `CONNECT, `OK ->
            (* Write the response and then switch to proxying the bytes *)
            Incoming.Response.write ~flush:true (fun _writer -> Lwt.return_unit) res incoming
            >>= fun () ->
            proxy_bytes ~incoming ~outgoing ~flow ~remote
            >>= fun () ->
            Log.debug (fun f -> f "%s: HTTP CONNECT complete" (description false));
            Lwt.return false
          | _, _ ->
            (* Otherwise stay in HTTP mode *)
            let reader = Outgoing.Response.make_body_reader res outgoing in
            Incoming.Response.write ~flush:true (fun writer ->
                match Cohttp.Request.meth req, Incoming.Response.has_body res with
                | `HEAD, `Yes ->
                  (* Bug in cohttp.1.0.2: according to Section 9.4 of RFC2616
                    https://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html
                    > The HEAD method is identical to GET except that the server
                    > MUST NOT return a message-body in the response.
                  *)
                  Log.debug (fun f -> f "%s: HEAD requests MUST NOT have response bodies" (description false));
                  Lwt.return_unit
                | _, `Yes     ->
                  Log.info (fun f -> f "%s: proxying body" (description false));
                  proxy_body_response_exn ~reader ~writer
                  >>= fun () ->
                  Lwt.return_unit
                | _, `No      ->
                  Log.info (fun f -> f "%s: no body to proxy" (description false));
                  Lwt.return_unit
                | _, `Unknown when connection_close ->
                  (* There may be a body between here and the EOF *)
                  Log.info (fun f -> f "%s: proxying until EOF" (description false));
                  proxy_body_response_exn ~reader ~writer
                | _, `Unknown ->
                  Log.warn (fun f ->
                      f "Response.has_body returned `Unknown: not sure \
                          what to do");
                  Lwt.return_unit
              ) res incoming
            >>= fun () ->
            Lwt.return (not connection_close)
      ) (fun e ->
        Log.warn (fun f -> f "proxy_request caught exception: %s" (Printexc.to_string e));
        Lwt.return false
      )

  let add_proxy_authorization proxy headers =
    let proxy_authorization = "Proxy-Authorization" in
    let headers = Cohttp.Header.remove headers proxy_authorization in
    match Uri.userinfo proxy with
      | None -> headers
      | Some s -> Cohttp.Header.add headers proxy_authorization ("Basic " ^ (Base64.encode_exn s))

  let address_of_proxy ~localhost_names ~localhost_ips proxy =
    match Uri.host proxy, Uri.port proxy with
    | None, _ ->
      Lwt.return (Error (`Msg ("HTTP proxy URI does not include a hostname: " ^ (Uri.to_string proxy))))
    | _, None ->
      Lwt.return (Error (`Msg ("HTTP proxy URI does not include a port: " ^ (Uri.to_string proxy))))
    | Some host, Some port ->
      let host =
        if List.mem (Dns.Name.of_string host) localhost_names
        then "localhost"
        else host in
      resolve_ip host
      >>= function
      | Error e -> Lwt.return (Error e)
      | Ok ip ->
        let ip =
          if List.mem ip localhost_ips
          then Ipaddr.(V4 V4.localhost)
          else ip in
        Lwt.return (Ok (ip, port))

  let send_error status incoming description msg () =
    let res = Cohttp.Response.make ~version:`HTTP_1_1 ~status () in
    Log.info (fun f -> f "%s: returning 503 Service_unavailable" description);
    Incoming.Response.write ~flush:true (fun writer ->
      Incoming.Response.write_body writer
        (error_html "ERROR: connection refused" msg)
    ) res incoming

  let tunnel_https_over_connect ~localhost_names ~localhost_ips ~dst proxy =
    let listeners _port =
      Log.debug (fun f -> f "HTTPS TCP handshake complete");
      let process flow =
        Lwt.catch
          (fun () ->
            Lwt.finalize
              (fun () ->
                address_of_proxy ~localhost_names ~localhost_ips proxy
                >>= function
                | Error (`Msg m) ->
                  Log.err (fun f -> f "HTTP proxy: cannot forward to %s: %s" (Uri.to_string proxy) m);
                  Lwt.return_unit
                | Ok ((ip, port) as address) ->
                  let host = Ipaddr.V4.to_string dst in
                  let description outgoing =
                    Fmt.strf "%s:443 %s %s:%d" host
                      (if outgoing then "-->" else "<--") (Ipaddr.to_string ip) port
                  in
                  Log.info (fun f -> f "%s: CONNECT" (description true));
                  let connect =
                    let host = Ipaddr.V4.to_string dst in
                    let port = 443 in
                    let uri = Uri.make ~host ~port () in
                    let headers = add_proxy_authorization proxy (Cohttp.Header.init ()) in
                    let request = Cohttp.Request.make ~meth:`CONNECT ~headers uri in
                    { request with Cohttp.Request.resource = host ^ ":" ^ (string_of_int port) }
                  in
                  Socket.Stream.Tcp.connect address >>= function
                  | Error _ ->
                    Log.err (fun f ->
                        f "Failed to connect to %s" (string_of_address address));
                    Lwt.return_unit
                  | Ok remote ->
                    let outgoing = Outgoing.C.create remote in
                    Lwt.finalize  (fun () ->
                        Outgoing.Request.write ~flush:true (fun _ -> Lwt.return_unit)
                          connect outgoing
                        >>= fun () ->
                        Outgoing.Response.read outgoing >>= function
                        | `Eof ->
                          Log.warn (fun f ->
                              f "EOF from %s" (string_of_address address));
                          Lwt.return_unit
                        | `Invalid x ->
                          Log.warn (fun f ->
                              f "Failed to parse HTTP response on port %s: %s"
                                (string_of_address address) x);
                          Lwt.return_unit
                        | `Ok res ->
                          Log.info (fun f ->
                              let open Cohttp.Response in
                              f "%s: %s %s"
                                (description false)
                                (Cohttp.Code.string_of_version res.version)
                                (Cohttp.Code.string_of_status res.status));
                          Log.debug (fun f ->
                              f "%s" (Sexplib.Sexp.to_string_hum
                                        (Cohttp.Response.sexp_of_t res)));
                          let incoming = Incoming.C.create flow in
                          proxy_bytes ~incoming ~outgoing ~flow ~remote
                      ) (fun () -> Socket.Stream.Tcp.close remote)
              ) (fun () -> Tcp.close flow)
          ) (fun e ->
            Log.warn (fun f -> f "tunnel_https_over_connect caught exception: %s" (Printexc.to_string e));
            Lwt.return_unit
          )
      in Some process
    in
    Lwt.return listeners

  (* A route is a decision about where to send an HTTP request. It depends on
     - whether a proxy is configured or not
     - the URI or the Host: header in the request
     - whether the request matches the proxy excludes or not *)
  type route = {
    next_hop_address: (Ipaddr.t * int);
    host: string;
    port: int;
    description: bool -> string;
    ty: [ `Origin | `Proxy ];
  }

  let get_host req =
    let uri = Cohttp.Request.uri req in
    (* A host in the URI takes precedence over a host: header *)
    match Uri.host uri, Cohttp.Header.get req.Cohttp.Request.headers "host" with
    | None, None ->
      Log.err (fun f -> f "HTTP request had no host in the URI nor in the host: header: %s"
        (Sexplib.Sexp.to_string_hum
          (Cohttp.Request.sexp_of_t req))
      );
      Error `Missing_host_header
    | Some host, _
    | None, Some host ->
      (* If the port is missing then it is assumed to be 80 *)
      let port = match Uri.port uri with None -> 80 | Some p -> p in
      Ok (host, port)

  let route ?(localhost_names=[]) ?(localhost_ips=[]) proxy exclude req =
    match get_host req with
    | Error x -> Lwt.return (Error x)
    | Ok (host, port) ->
      Log.debug (fun f -> f "host from request = %s:%d" host port);
      (* A proxy URL must have both a host and a port to be useful *)
      let hostport_from_proxy = match proxy with
        | None -> None
        | Some uri ->
          begin match Uri.host uri, Uri.port uri with
          | Some host, Some port ->
            Log.debug (fun f -> f "upstream proxy is %s:%d" host port);
            Some (host, port)
          | Some host, None ->
            Log.warn (fun f -> f "HTTP proxy %s has no port number" host);
            None
          | _, _ ->
            Log.warn (fun f -> f "HTTP proxy has no host");
            None
          end in
      let hostport_and_ty = match hostport_from_proxy with
        (* No proxy means we must send to the origin server *)
        | None -> Some ((host, port), `Origin)
        (* If a proxy is configured it depends on whether the request matches the excludes *)
        | Some proxy ->
          if Exclude.matches host exclude
          then Some ((host, port), `Origin)
          else Some (proxy, `Proxy) in
      begin match hostport_and_ty with
      | None ->
        Log.err (fun f -> f "Failed to route request: %s" (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t req)));
        Lwt.return (Error `Missing_host_header)
      | Some ((next_hop_host, next_hop_port), ty) ->
        let next_hop_host =
          if List.mem (Dns.Name.of_string next_hop_host) localhost_names
          then "localhost"
          else next_hop_host in
        Log.debug (fun f -> f "next_hop_address is %s:%d" next_hop_host next_hop_port);
        resolve_ip next_hop_host
        >>= function
        | Error (`Msg m) ->
          Lwt.return (Error (`Msg m))
        | Ok next_hop_ip ->
          let next_hop_ip =
            if List.mem next_hop_ip localhost_ips
            then Ipaddr.(V4 V4.localhost)
            else next_hop_ip in
          let description outgoing =
            Printf.sprintf "HTTP proxy %s %s:%d Host:%s:%d (%s)"
              (if outgoing then "-->" else "<--") (Ipaddr.to_string next_hop_ip) next_hop_port host port
              (match ty with `Origin -> "Origin" | `Proxy -> "Proxy") in
          Lwt.return (Ok { next_hop_address = (next_hop_ip, next_hop_port); host; port; description; ty })
      end

  let fetch ?localhost_names ?localhost_ips ~flow proxy exclude incoming req =
    let uri = Cohttp.Request.uri req in
    let meth = Cohttp.Request.meth req in
    route ?localhost_names ?localhost_ips proxy exclude req
    >>= function
    | Error `Missing_host_header ->
      send_error `Bad_request incoming "HTTP proxy"
        "The HTTP request must contain an absolute URI e.g. http://github.com/moby/vpnkit" ()
      >>= fun () ->
      Lwt.return false
    | Error (`Msg m) ->
      send_error `Service_unavailable incoming "HTTP proxy" m ()
      >>= fun () ->
      Lwt.return false
    | Ok { next_hop_address; host; port; description; ty } ->
      Log.info (fun f ->
          f "%s: %s %s"
            (description true)
            (Cohttp.(Code.string_of_method meth))
            (Uri.path uri));
      Log.debug (fun f ->
          f "%s: received %s"
            (description false)
            (Sexplib.Sexp.to_string_hum
              (Cohttp.Request.sexp_of_t req))
          );
      begin Socket.Stream.Tcp.connect next_hop_address >>= function
      | Error _ ->
        Log.err (fun f ->
            f "%s: Failed to connect to %s" (description true) (string_of_address next_hop_address));
        send_error `Service_unavailable incoming "HTTP proxy"
          (Printf.sprintf "The proxy could not connect ot %s" (string_of_address next_hop_address)) ()
        >>= fun () ->
        Lwt.return false
      | Ok remote ->
        Lwt.finalize  (fun () ->
          Log.info (fun f ->
              f "%s: Successfully connected to %s" (description true) (string_of_address next_hop_address));
          let outgoing = Outgoing.C.create remote in
          match ty, Cohttp.Request.meth req with
          | `Origin, `CONNECT ->
            (* return 200 OK and start a TCP proxy *)
            let response = "HTTP/1.1 200 OK\r\n\r\n" in
            Incoming.C.write_string incoming response 0 (String.length response);
            begin Incoming.C.flush incoming >>= function
            | Error _ ->
              Log.err (fun f -> f "%s: failed to return 200 OK" (description false));
              Lwt.return false
            | Ok () ->
              proxy_bytes ~incoming ~outgoing ~flow ~remote
              >>= fun () ->
              Log.debug (fun f -> f "%s: HTTP CONNECT complete" (description false));
              Lwt.return false
            end
          | _, _ ->
            (* If the request is to an origin server we should convert back to a relative URI
               and a Host: header.
               If the request is to a proxy then the URI should be absolute and should match
               the Host: header.
               In all cases we should make sure the host header is correct. *)
            let host_and_port = host ^ (match port with 80 -> "" | _ -> ":" ^ (string_of_int port)) in
            let headers = Cohttp.Header.replace req.Cohttp.Request.headers "host" host_and_port in
            (* If the request is to a proxy then we should add a Proxy-Authorization header *)
            let headers = match proxy with
              | None -> headers
              | Some proxy -> add_proxy_authorization proxy headers in
            let resource = match ty, Cohttp.Request.meth req with
              | `Origin, _ -> Uri.path_and_query uri
              | `Proxy, `CONNECT -> host_and_port
              | `Proxy, _ -> Uri.with_scheme (Uri.with_host (Uri.with_port uri (Some port)) (Some host)) (Some "http") |> Uri.to_string in
            let req = { req with Cohttp.Request.headers; resource } in
            Log.debug (fun f -> f "%s: sending %s"
              (description false)
              (Sexplib.Sexp.to_string_hum
                (Cohttp.Request.sexp_of_t req))
            );
            proxy_request ~description ~incoming ~outgoing ~flow ~remote ~req
        ) (fun () -> Socket.Stream.Tcp.close remote)
      end

  (* A regular, non-transparent HTTP proxy implementation.
     If [proxy] is [None] then requests will be sent to origin servers;
     otherwise they will be sent to the upstream proxy. *)
  let explicit_proxy ~localhost_names ~localhost_ips proxy exclude () =
    let listeners _port =
      Log.debug (fun f -> f "HTTP TCP handshake complete");
      let process flow =
        Lwt.catch
          (fun () ->
            Lwt.finalize (fun () ->
                let incoming = Incoming.C.create flow in
                let rec loop () =
                  Incoming.Request.read incoming >>= function
                  | `Eof -> Lwt.return_unit
                  | `Invalid x ->
                    Log.warn (fun f ->
                        f "HTTP proxy failed to parse HTTP request: %s"
                          x);
                    Lwt.return_unit
                  | `Ok req ->
                    fetch ~localhost_names ~localhost_ips ~flow proxy exclude incoming req
                    >>= function
                    | true ->
                      (* keep the connection open, read more requests *)
                      loop ()
                    | false ->
                      Log.debug (fun f -> f "HTTP session complete, closing connection");
                      Lwt.return_unit in
                  loop ()
              ) (fun () -> Tcp.close flow)
          ) (fun e ->
            Log.warn (fun f -> f "explicit_proxy caught exception: %s" (Printexc.to_string e));
            Lwt.return_unit
          )
      in
      Some process
    in
    Lwt.return listeners

  let transparent_http ~dst ~localhost_names ~localhost_ips proxy exclude =
    let listeners _port =
      Log.debug (fun f -> f "HTTP TCP handshake complete");
      let process flow =
        Lwt.catch
          (fun () ->
            Lwt.finalize (fun () ->
              let incoming = Incoming.C.create flow in
              let rec loop () =
                Incoming.Request.read incoming >>= function
                | `Eof -> Lwt.return_unit
                | `Invalid x ->
                  Log.warn (fun f ->
                      f "Failed to parse HTTP request on port %a:80: %s"
                        Ipaddr.V4.pp dst x);
                  Lwt.return_unit
                | `Ok req ->
                  (* If there is no Host: header or host in the URI then add a
                    Host: header with the destination IP address -- this is not perfect
                    but better than nothing and the majority of people will supply a Host:
                    header these days because otherwise virtual hosts don't work *)
                  let req =
                    match get_host req with
                    | Error `Missing_host_header ->
                      { req with Cohttp.Request.headers = Cohttp.Header.replace req.headers "host" (Ipaddr.V4.to_string dst) }
                    | Ok _ -> req in
                  fetch ~localhost_names ~localhost_ips ~flow (Some proxy) exclude incoming req
                  >>= function
                  | true ->
                    (* keep the connection open, read more requests *)
                    loop ()
                  | false ->
                    Log.debug (fun f -> f "HTTP session complete, closing connection");
                    Lwt.return_unit in
                loop ()
              ) (fun () -> Tcp.close flow)
          ) (fun e ->
            Log.warn (fun f -> f "transparent_http caught exception: %s" (Printexc.to_string e));
            Lwt.return_unit
          )
      in Some process
    in
    Lwt.return listeners

  let transparent_proxy_handler ~localhost_names ~localhost_ips ~dst:(ip, port) ~t =
    match t.http, t.https with
    | Some proxy, _ when List.mem port t.transparent_http_ports -> Some (transparent_http ~dst:ip ~localhost_names ~localhost_ips proxy t.exclude)
    | _, Some proxy when List.mem port t.transparent_https_ports ->
      if Exclude.matches (Ipaddr.V4.to_string ip) t.exclude
      then None
      else Some (tunnel_https_over_connect ~localhost_names ~localhost_ips ~dst:ip proxy)
    | _, _ -> None

  let explicit_proxy_handler ~localhost_names ~localhost_ips ~dst:(_, port) ~t =
    match port, t.http, t.https with
    | 3128, proxy, _
    | 3129, _, proxy -> Some (explicit_proxy ~localhost_names ~localhost_ips proxy t.exclude ())
    (* For other ports, refuse the connection *)
    | _, _, _ -> None
end

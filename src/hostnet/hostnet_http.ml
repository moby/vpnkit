let src =
  let src = Logs.Src.create "http" ~doc:"Transparently proxy HTTP" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Make
    (Ip: V1_LWT.IPV4 with type prefix = Ipaddr.V4.t)
    (Udp: V1_LWT.UDPV4)
    (Tcp:Mirage_flow_s.SHUTDOWNABLE)
    (Socket: Sig.SOCKETS)
    (Dns_resolver: Sig.DNS)
    = struct

  type address = Ipaddr.t * int
  let string_of_address (ip, port)  = Printf.sprintf "%s:%d" (Ipaddr.to_string ip) port

  type t = {
    http: address option;
    https: address option;
    exclude: string list;
  }

  let parse_host_port x : (Ipaddr.t * int) option Error.t =
    (* host:port or [host]:port *)
    let find_host name_or_ip =
      match Ipaddr.of_string name_or_ip with
      | None ->
        let open Lwt.Infix in
        let open Dns.Packet in
        let question = make_question ~q_class:Q_IN Q_A (Dns.Name.of_string name_or_ip) in
        begin Dns_resolver.resolve question
        >>= function
        | { cls = RR_IN; rdata = A ipv4; _ } :: _ ->
          Lwt.return (Ok (Ipaddr.V4 ipv4))
        | _ -> Lwt.return (Error (`Msg ("Failed to lookup host: " ^ name_or_ip)))
        end
      | Some x -> Lwt.return (Ok x) in
    let parse_port port =
      match int_of_string port with
      | x -> Lwt.return (Ok x)
      | exception _ -> Lwt.return (Error (`Msg ("Failed to parse port: " ^ port))) in
    (* Is it a URL? *)
    let uri = Uri.of_string x in
    begin match Uri.host uri, Uri.port uri with
    | Some host, Some port ->
      let open Error.Infix in
      find_host host
      >>= fun ip ->
      Lwt.return (Ok (Some (ip, port)))
    | _, _ ->
      let open Astring in
      begin match String.cuts ~sep:":" x with
      | [] -> Lwt.return (Error (`Msg ("Failed to find a :port in " ^ x)))
      | [host; port] ->
        let open Error.Infix in
        find_host host
        >>= fun ip ->
        parse_port port
        >>= fun port ->
        Lwt.return (Ok (Some (ip, port)))
      | _ -> Lwt.return (Error (`Msg ("Failed to parse proxy address: " ^ x)))
      end
    end

  let to_json t =
    let open Ezjsonm in
    let http    = match t.http  with None -> [] | Some x -> [ "http",  string @@ string_of_address x ] in
    let https   = match t.https with None -> [] | Some x -> [ "https", string @@ string_of_address x ] in
    let exclude = [ "exclude", strings t.exclude ] in
    dict (http @ https @ exclude)
  let of_json j =
    let open Ezjsonm in
    let http  = try Some (get_string @@ find j [ "http" ])  with Not_found -> None in
    let https = try Some (get_string @@ find j [ "https" ]) with Not_found -> None in
    let exclude = try get_strings @@ find j [ "exclude" ] with _ -> [] in
    let open Error.Infix in
    (match http with None -> Lwt.return (Ok None) | Some x -> parse_host_port x)
    >>= fun http ->
    (match https with None -> Lwt.return (Ok None) | Some x -> parse_host_port x)
    >>= fun https ->
    Lwt.return (Ok { http; https; exclude })

  let to_string t = Ezjsonm.to_string ~minify:false @@ to_json t

  let create ?http ?https ?exclude:_ () : t Error.t =
    let open Error.Infix in
    ( match http with
      | None -> Lwt.return (Ok None)
      | Some http -> parse_host_port http )
    >>= fun http ->
    ( match https with
      | None -> Lwt.return (Ok None)
      | Some https -> parse_host_port https )
    >>= fun https ->
    (* FIXME: parse excludes *)
    let exclude = [] in
    let t = { http; https; exclude } in
    Log.info (fun f -> f "HTTP proxy settings changed to: %s" (to_string t));
    Lwt.return (Ok t)

  module Incoming = struct
    module C = Channel.Make(Tcp)
    module IO = Cohttp_mirage_io.Make(C)
    module Request = Cohttp.Request.Make(IO)
    module Response = Cohttp.Response.Make(IO)
  end
  module Outgoing = struct
    module C = Channel.Make(Socket.Stream.Tcp)
    module IO = Cohttp_mirage_io.Make(C)
    module Request = Cohttp.Request.Make(IO)
    module Response = Cohttp.Response.Make(IO)
  end

  let choose_proxy_for ~t _uri = t.http

  let http ~dst ~t =
    let open Lwt.Infix in
    let listeners _port =
      Log.debug (fun f -> f "HTTP TCP handshake complete");
      Some (fun flow ->
        Lwt.finalize
          (fun () ->
            let incoming = Incoming.C.create flow in
            let proxy_one () =
              Incoming.Request.read incoming
              >>= function
              | `Eof -> Lwt.return_unit
              | `Invalid x ->
                Log.warn (fun f -> f "Failed to parse HTTP request on port %s:80: %s" (Ipaddr.V4.to_string dst) x);
                Lwt.return_unit
              | `Ok req ->
                (* The scheme from cohttp is missing. If we send to an HTTP proxy
                   then we need it. *)
                let uri = Uri.with_scheme (Cohttp.Request.uri req) (Some "http") in
                (* Log the request to the console *)
                let address = match choose_proxy_for ~t uri with
                  | None -> Ipaddr.V4 dst, 80 (* direct connection *)
                  | Some (ip, port) -> ip, port in
                Log.info (fun f -> f "%s:80 --> %s:%d %s %s %s\n%!"
                  (Ipaddr.V4.to_string dst)
                  (Ipaddr.to_string @@ fst address)
                  (snd address)
                  (Cohttp.(Code.string_of_method (Cohttp.Request.meth req)))
                  (Uri.to_string uri)
                  (Sexplib.Sexp.to_string_hum (Cohttp.Request.sexp_of_t req)));
                begin
                    Socket.Stream.Tcp.connect address
                    >>= function
                    | Error _ ->
                      Log.err (fun f -> f "Failed to connect to %s" (string_of_address address));
                      Lwt.return_unit
                    | Ok remote ->
                      (* Make the resource a full URI *)
                      let req = { req with Cohttp.Request.resource = Uri.to_string uri } in

                      Lwt.finalize
                        (fun () ->
                          let outgoing = Outgoing.C.create remote in
                          let reader = Incoming.Request.make_body_reader req incoming in
                          Outgoing.Request.write ~flush:true
                            (fun writer ->
                              let rec proxy_body () =
                                Incoming.Request.read_body_chunk reader
                                >>= function
                                | Cohttp.Transfer.Done ->
                                  Lwt.return_unit
                                | Cohttp.Transfer.Chunk x ->
                                  Outgoing.Request.write_body writer x
                                  >>= fun () ->
                                  proxy_body ()
                                | Cohttp.Transfer.Final_chunk x ->
                                  Outgoing.Request.write_body writer x in
                              match Incoming.Request.has_body req with
                              | `Yes -> proxy_body ()
                              | `No -> Lwt.return_unit
                              | `Unknown ->
                                Log.warn (fun f -> f "Request.has_body returned `Unknown: not sure what to do");
                                Lwt.return_unit
                            ) req outgoing
                          >>= fun () ->
                          Outgoing.Response.read outgoing
                          >>= function
                          | `Eof ->
                            Log.warn (fun f -> f "EOF from %s" (string_of_address address));
                            Lwt.return_unit
                          | `Invalid x ->
                            Log.warn (fun f -> f "Failed to parse HTTP response on port %s: %s" (string_of_address address) x);
                            Lwt.return_unit
                          | `Ok res ->
                            Log.info (fun f -> f "<-- %s %s %s\n%!"
                              (Cohttp.Code.string_of_status res.Cohttp.Response.status)
                              (Cohttp.Code.string_of_version res.Cohttp.Response.version)
                              (Sexplib.Sexp.to_string_hum (Cohttp.Response.sexp_of_t res)));
                            let reader = Outgoing.Response.make_body_reader res outgoing in
                            Incoming.Response.write ~flush:true
                              (fun writer ->
                                let rec proxy_body () =
                                  Outgoing.Response.read_body_chunk reader
                                  >>= function
                                  | Cohttp.Transfer.Done ->
                                    Lwt.return_unit
                                  | Cohttp.Transfer.Chunk x ->
                                    Incoming.Response.write_body writer x
                                    >>= fun () ->
                                    proxy_body ()
                                  | Cohttp.Transfer.Final_chunk x ->
                                    Incoming.Response.write_body writer x in
                                match Incoming.Response.has_body res with
                                | `Yes -> proxy_body ()
                                | `No -> Lwt.return_unit
                                | `Unknown ->
                                  Log.warn (fun f -> f "Response.has_body returned `Unknown: not sure what to do");
                                  Lwt.return_unit
                              ) res incoming
                        ) (fun () ->
                          Socket.Stream.Tcp.close remote
                        )
                  end in
          let rec loop () =
            proxy_one ()
            >>= fun () ->
            loop () in
          loop ()
        ) (fun () ->
          Tcp.close flow
        )
      ) in
    Lwt.return listeners

  let https ~dst ~t =
    let open Lwt.Infix in
    let listeners _port =
      Log.debug (fun f -> f "HTTPS TCP handshake complete");
      Some (fun flow ->
        Lwt.finalize
          (fun () ->
            match t.https with
            | None ->
              Log.warn (fun f -> f "Failed to proxy https: no proxy defined");
              Lwt.return_unit
            | Some ((ip, port) as address) ->
              let host = Ipaddr.V4.to_string dst in
              Log.info (fun f -> f "%s:443 --> %s:%d\n%!" host (Ipaddr.to_string ip) port);
              let connect = Cohttp.Request.make ~meth:`CONNECT (Uri.make ()) in
              let connect = { connect with Cohttp.Request.resource = Printf.sprintf "%s:%d" (Ipaddr.V4.to_string dst) 443 } in
              Socket.Stream.Tcp.connect address
              >>= function
              | Error _ ->
                Log.err (fun f -> f "Failed to connect to %s" (string_of_address address));
                Lwt.return_unit
              | Ok remote ->
                let outgoing = Outgoing.C.create remote in
                Lwt.finalize
                  (fun () ->
                    Outgoing.Request.write ~flush:true (fun _ -> Lwt.return_unit) connect outgoing
                    >>= fun () ->
                    Outgoing.Response.read outgoing
                    >>= function
                    | `Eof ->
                      Log.warn (fun f -> f "EOF from %s" (string_of_address address));
                      Lwt.return_unit
                    | `Invalid x ->
                      Log.warn (fun f -> f "Failed to parse HTTP response on port %s: %s" (string_of_address address) x);
                      Lwt.return_unit
                    | `Ok res ->
                      begin
                        Log.info (fun f -> f "<-- %s %s %s\n%!"
                          (Cohttp.Code.string_of_status res.Cohttp.Response.status)
                          (Cohttp.Code.string_of_version res.Cohttp.Response.version)
                          (Sexplib.Sexp.to_string_hum (Cohttp.Response.sexp_of_t res)));
                        (* Since we've already layered a channel on top, we can't
                           use the Mirage_flow.proxy since it would miss the contents
                           already buffered. Therefore we write out own channel-level
                           proxy here: *)
                        let incoming = Incoming.C.create flow in
                        let a_t =
                          let rec loop () =
                            Lwt.catch
                              (fun () ->
                                Outgoing.C.read_some outgoing
                                >>= fun buf ->
                                Incoming.C.write_buffer incoming buf;
                                Incoming.C.flush incoming
                                >>= fun () ->
                                Lwt.return true
                              ) (function
                                | End_of_file -> Lwt.return false
                                | e ->
                                  Log.warn (fun f -> f "Possibly unexpected exeption %s in proxy" (Printexc.to_string e));
                                  Lwt.return false)
                            >>= fun continue ->
                            if continue then loop () else begin
                              Tcp.shutdown_write flow
                              >>= fun () ->
                              Lwt.return_unit
                            end in
                          loop () in
                        let b_t =
                          let rec loop () =
                            Lwt.catch
                              (fun () ->
                                Incoming.C.read_some incoming
                                >>= fun buf ->
                                Outgoing.C.write_buffer outgoing buf;
                                Outgoing.C.flush outgoing
                                >>= fun () ->
                                Lwt.return true
                              ) (function
                                | End_of_file -> Lwt.return false
                                | e ->
                                  Log.warn (fun f -> f "Possibly unexpected exeption %s in proxy" (Printexc.to_string e));
                                  Lwt.return false)
                            >>= fun continue ->
                            if continue then loop () else begin
                              Socket.Stream.Tcp.shutdown_write remote
                              >>= fun () ->
                              Lwt.return_unit
                            end in
                          loop () in
                        Lwt.join [ a_t; b_t ]
                        >>= fun () ->
                        Lwt.return_unit
                      end
                ) (fun () ->
                  Socket.Stream.Tcp.close remote
                )
          ) (fun () ->
            Tcp.close flow
          )
        ) in
    Lwt.return listeners

  let handle ~dst:(ip, port) ~t =
    if port = 80 && t.http <> None
    then Some (http ~dst:ip ~t)
    else if port = 443 && t.https <> None
    then Some (https ~dst:ip ~t)
    else None
end

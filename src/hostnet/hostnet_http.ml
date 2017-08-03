open Lwt.Infix
open Astring

let src =
  let src = Logs.Src.create "http" ~doc:"Transparently proxy HTTP" in
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
      | "*" -> Any
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

    let of_string s =
      match Ipaddr.V4.Prefix.of_string s with
      | None ->
        let bits = Astring.String.cuts ~sep:"." s in
        Subdomain (List.map Element.of_string bits)
      | Some prefix -> CIDR prefix

    let to_string = function
    | Subdomain x ->
      "Subdomain " ^ String.concat ~sep:"." @@ List.map Element.to_string x
    | CIDR prefix -> "CIDR " ^ Ipaddr.V4.Prefix.to_string prefix

    let matches dst req = function
    | CIDR prefix -> Ipaddr.V4.Prefix.mem dst prefix
    | Subdomain domains ->
      begin match req with
      | Some req ->
        let h = req.Cohttp.Request.headers in
        begin match Cohttp.Header.get h "host" with
        | Some host ->
          let bits = Astring.String.cuts ~sep:"." host in
          (* does 'bits' match 'domains' *)
          let rec loop bits domains = match bits, domains with
          | _, [] -> true
          | [], _ :: _ -> false
          | b :: bs, d :: ds -> Element.matches b d && loop bs ds in
          loop (List.rev bits) (List.rev domains)
        | None -> false
        end
      | None -> false
      end
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

  let matches dst req t =
    List.fold_left (||) false (List.map (One.matches dst req) t)

end

module Make
    (Ip: Mirage_protocols_lwt.IPV4)
    (Udp: Mirage_protocols_lwt.UDPV4)
    (Tcp:Mirage_flow_lwt.SHUTDOWNABLE)
    (Socket: Sig.SOCKETS)
    (Dns_resolver: Sig.DNS)
= struct

  type address = Ipaddr.t * int

  let string_of_address (ip, port) = Fmt.strf "%s:%d" (Ipaddr.to_string ip) port

  type t = {
    http: address option;
    https: address option;
    exclude: Exclude.t;
  }

  let parse_host_port x =
    (* host:port or [host]:port *)
    let find_host name_or_ip =
      match Ipaddr.of_string name_or_ip with
      | None ->
        let open Dns.Packet in
        let question =
          make_question ~q_class:Q_IN Q_A (Dns.Name.of_string name_or_ip)
        in
        begin Dns_resolver.resolve question >>= function
          | { cls = RR_IN; rdata = A ipv4; _ } :: _ ->
            Lwt.return (Ok (Ipaddr.V4 ipv4))
          | _ -> errorf "Failed to lookup host: %s" name_or_ip
        end
      | Some x -> Lwt.return (Ok x)
    in
    let parse_port port =
      match int_of_string port with
      | x -> Lwt.return (Ok x)
      | exception _ -> errorf "Failed to parse port: %s" port
    in
    (* Is it a URL? *)
    let uri = Uri.of_string x in
    match Uri.host uri, Uri.port uri with
    | Some host, Some port ->
      let open Lwt_result.Infix in
      find_host host >|= fun ip ->
      Some (ip, port)
    | _, _ ->
      match String.cuts ~sep:":" x with
      | [] -> errorf "Failed to find a :port in %s" x
      | [host; port] ->
        let open Lwt_result.Infix in
        find_host host >>= fun ip ->
        parse_port port >|= fun port ->
        Some (ip, port)
      | _ -> errorf "Failed to parse proxy address: %s" x

  let to_json t =
    let open Ezjsonm in
    let http = match t.http with
    | None   -> []
    | Some x -> [ "http",  string @@ string_of_address x ]
    in
    let https = match t.https with
    | None   -> []
    | Some x -> [ "https", string @@ string_of_address x ]
    in
    let exclude = [ "exclude", string @@ Exclude.to_string t.exclude ] in
    dict (http @ https @ exclude)

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
    let open Lwt_result.Infix in
    (match http with
    | None -> Lwt.return (Ok None)
    | Some x -> parse_host_port x)
    >>= fun http ->
    (match https with
    | None -> Lwt.return (Ok None)
    | Some x -> parse_host_port x)
    >>= fun https ->
    Lwt.return (Ok { http; https; exclude })

  let to_string t = Ezjsonm.to_string ~minify:false @@ to_json t

  let create ?http ?https ?exclude:_ () =
    let open Lwt_result.Infix in
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
    module C = Mirage_channel_lwt.Make(Tcp)
    module IO = Cohttp_mirage_io.Make(C)
    module Request = Cohttp.Request.Make(IO)
    module Response = Cohttp.Response.Make(IO)
  end
  module Outgoing = struct
    module C = Mirage_channel_lwt.Make(Socket.Stream.Tcp)
    module IO = Cohttp_mirage_io.Make(C)
    module Request = Cohttp.Request.Make(IO)
    module Response = Cohttp.Response.Make(IO)
  end

  let rec proxy_body_request ~reader ~writer =
    let open Cohttp.Transfer in
    Incoming.Request.read_body_chunk reader >>= function
    | Done          -> Lwt.return_unit
    | Final_chunk x -> Outgoing.Request.write_body writer x
    | Chunk x       ->
      Outgoing.Request.write_body writer x >>= fun () ->
      proxy_body_request ~reader ~writer

  let rec proxy_body_response ~reader ~writer =
    let open Cohttp.Transfer in
    Outgoing.Response.read_body_chunk reader  >>= function
    | Done          -> Lwt.return_unit
    | Final_chunk x -> Incoming.Response.write_body writer x
    | Chunk x       ->
      Incoming.Response.write_body writer x >>= fun () ->
      proxy_body_response ~reader ~writer

  let proxy_one ~dst ~t h incoming =
    Incoming.Request.read incoming >>= function
    | `Eof -> Lwt.return_unit
    | `Invalid x ->
      Log.warn (fun f ->
          f "Failed to parse HTTP request on port %a:80: %s"
            Ipaddr.V4.pp_hum dst x);
      Lwt.return_unit
    | `Ok req ->
      (* The scheme from cohttp is missing. If we send to an HTTP
         proxy then we need it. *)
      let uri = Uri.with_scheme (Cohttp.Request.uri req) (Some "http") in
      let address =
        if Exclude.matches dst (Some req) t.exclude
        then Ipaddr.V4 dst, 80 (* direct connection *)
        else h
      in
      (* Log the request to the console *)
      let description outgoing =
        Printf.sprintf "%s:80 %s %s:%d Host:%s"
          (Ipaddr.V4.to_string dst)
          (if outgoing then "-->" else "<--")
          (Ipaddr.to_string @@ fst address)
          (snd address)
          (match Uri.host uri with Some x -> x | None -> "(unknown host)")
      in
      Log.info (fun f ->
          f "%s: %s %s"
            (description true)
            (Cohttp.(Code.string_of_method (Cohttp.Request.meth req)))
            (Uri.path uri));
      Socket.Stream.Tcp.connect address >>= function
      | Error _ ->
        Log.err (fun f ->
            f "Failed to connect to %s" (string_of_address address));
        Lwt.return_unit
      | Ok remote ->
        (* Make the resource a full URI *)
        let req = { req with Cohttp.Request.resource = Uri.to_string uri } in
        Lwt.finalize (fun () ->
            let outgoing = Outgoing.C.create remote in
            let reader = Incoming.Request.make_body_reader req incoming in
            Outgoing.Request.write ~flush:true (fun writer ->
                match Incoming.Request.has_body req with
                | `Yes     -> proxy_body_request ~reader ~writer
                | `No      -> Lwt.return_unit
                | `Unknown ->
                  Log.warn (fun f ->
                      f "Request.has_body returned `Unknown: not sure what \
                         to do");
                  Lwt.return_unit
              ) req outgoing
            >>= fun () ->
            Outgoing.Response.read outgoing >>= function
            | `Eof ->
              Log.warn (fun f -> f "EOF from %s" (string_of_address address));
              Lwt.return_unit
            | `Invalid x ->
              Log.warn (fun f ->
                  f "Failed to parse HTTP response on port %s: %s"
                    (string_of_address address) x);
              Lwt.return_unit
            | `Ok res ->
              Log.info (fun f ->
                  f "%s: %s %s"
                    (description false)
                    (Cohttp.Code.string_of_version res.Cohttp.Response.version)
                    (Cohttp.Code.string_of_status res.Cohttp.Response.status));
              Log.debug (fun f ->
                  f "%s" (Sexplib.Sexp.to_string_hum
                            (Cohttp.Response.sexp_of_t res)));
              let reader = Outgoing.Response.make_body_reader res outgoing in
              Incoming.Response.write ~flush:true (fun writer ->
                  match Incoming.Response.has_body res with
                  | `Yes     -> proxy_body_response ~reader ~writer
                  | `No      -> Lwt.return_unit
                  | `Unknown ->
                    Log.warn (fun f ->
                        f "Response.has_body returned `Unknown: not sure \
                           what to do");
                    Lwt.return_unit
                ) res incoming
          ) (fun () -> Socket.Stream.Tcp.close remote)

  let http ~dst ~t h =
    let listeners _port =
      Log.debug (fun f -> f "HTTP TCP handshake complete");
      let f flow =
        Lwt.finalize (fun () ->
            let incoming = Incoming.C.create flow in
            let rec loop () = proxy_one ~dst ~t h incoming >>= loop in
            loop ()
          ) (fun () -> Tcp.close flow)
      in
      Some f
    in
    Lwt.return listeners

  (* forward outgoing to ingoing *)
  let a_t flow ~incoming ~outgoing =
    let warn pp e =
      Log.warn (fun f -> f "Unexpected exeption %a in proxy" pp e);
    in
    let rec loop () =
      (Outgoing.C.read_some outgoing >>= function
        | Ok `Eof        -> Lwt.return false
        | Error e        -> warn Outgoing.C.pp_error e; Lwt.return false
        | Ok (`Data buf) ->
          Incoming.C.write_buffer incoming buf;
          Incoming.C.flush incoming >|= function
          | Ok ()         -> true
          | Error `Closed -> false
          | Error e       -> warn Incoming.C.pp_write_error e; false
      ) >>= fun continue ->
      if continue then loop () else Tcp.shutdown_write flow
    in
    loop ()

  (* forward ingoing to outgoing *)
  let b_t remote ~incoming ~outgoing =
    let warn pp e =
      Log.warn (fun f -> f "Unexpected exeption %a in proxy" pp e);
    in
    let rec loop () =
      (Incoming.C.read_some incoming >>= function
        | Ok `Eof        -> Lwt.return false
        | Error e        -> warn Incoming.C.pp_error e; Lwt.return false
        | Ok (`Data buf) ->
          Outgoing.C.write_buffer outgoing buf;
          Outgoing.C.flush outgoing >|= function
          | Ok ()         -> true
          | Error `Closed -> false
          | Error e       -> warn Outgoing.C.pp_write_error e; false
      ) >>= fun continue ->
      if continue then loop () else Socket.Stream.Tcp.shutdown_write remote
    in
    loop ()

  let https ~dst ((ip, port) as address) =
    let listeners _port =
      Log.debug (fun f -> f "HTTPS TCP handshake complete");
      let f flow =
        Lwt.finalize (fun () ->
            let host = Ipaddr.V4.to_string dst in
            let description outgoing =
              Fmt.strf "%s:443 %s %s:%d" host
                (if outgoing then "-->" else "<--") (Ipaddr.to_string ip) port
            in
            Log.info (fun f -> f "%s: CONNECT" (description true));
            let connect =
              let connect = Cohttp.Request.make ~meth:`CONNECT (Uri.make ()) in
              let resource = Fmt.strf "%s:%d" (Ipaddr.V4.to_string dst) 443 in
              { connect with Cohttp.Request.resource }
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
                    (* Since we've already layered a channel on top,
                       we can't use the Mirage_flow.proxy since it
                       would miss the contents already
                       buffered. Therefore we write out own
                       channel-level proxy here: *)
                    let incoming = Incoming.C.create flow in
                    Lwt.join [
                      a_t flow ~incoming ~outgoing;
                      b_t remote ~incoming ~outgoing
                    ]
                ) (fun () -> Socket.Stream.Tcp.close remote)
          ) (fun () -> Tcp.close flow)
      in Some f
    in
    Lwt.return listeners

  let handle ~dst:(ip, port) ~t =
    match port, t.http, t.https with
    | 80, Some h, _ -> Some (http ~dst:ip ~t h)
    | 443, _, Some h ->
      if Exclude.matches ip None t.exclude
      then None
      else Some (https ~dst:ip h)
    | _, _, _ -> None
end

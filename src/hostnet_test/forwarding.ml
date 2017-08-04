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

module Channel = Mirage_channel_lwt.Make(Host.Sockets.Stream.Tcp)

module ForwardServer = struct
  (** Accept connections, read the forwarding header and run a proxy *)

  module Proxy =
    Mirage_flow_lwt.Proxy
      (Mclock)(Host.Sockets.Stream.Tcp)(Host.Sockets.Stream.Tcp)

  let accept flow =
    let sizeof = 1 + 2 + 4 + 2 in
    let header = Cstruct.create sizeof in
    Host.Sockets.Stream.Tcp.read_into flow header >>= function
    | Ok `Eof -> failwith "EOF"
    | Error e -> Fmt.kstrf failwith "%a" Host.Sockets.Stream.Tcp.pp_error e
    | Ok (`Data ()) ->
      let ip_len = Cstruct.LE.get_uint16 header 1 in
      let ip =
        let bytes = Cstruct.(to_string @@ sub header 3 ip_len) in
        if String.length bytes = 4
        then Ipaddr.V4.of_bytes_exn bytes
        else assert false in (* IPv4 only *)
      let port = Cstruct.LE.get_uint16 header 7 in
      assert (Cstruct.get_uint8 header 0 == 1); (* TCP only *)

      Host.Sockets.Stream.Tcp.connect (Ipaddr.V4 ip, port) >>= function
      | Error (`Msg x) -> failwith x
      | Ok remote ->
        Mclock.connect () >>= fun clock ->
        Lwt.finalize (fun () ->
            Proxy.proxy clock flow remote >>= function
            | Error e -> Fmt.kstrf failwith "%a" Proxy.pp_error e
            | Ok (_l_stats, _r_stats) -> Lwt.return ()
          ) (fun () ->
            Host.Sockets.Stream.Tcp.close remote
          )

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
    Mclock.connect () >>= fun clock ->
    let ports = Ports.make clock in
    Ports.set_context ports "";
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

module LocalClient = struct
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

module LocalServer = struct
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
      | "tcp" :: ip :: port :: _ ->
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

let test_one_forward () =
  let t = LocalServer.with_server (fun server ->
      PortsServer.with_server (fun ports_port ->
          ForwardControl.with_connection ports_port (fun connection ->
              let name = "tcp:127.0.0.1:0:" ^ LocalServer.to_string server in
              ForwardControl.with_forward connection name (fun ip port ->
                  LocalClient.connect (ip, port)
                  >>= fun client ->
                  http_get client
                  >>= fun () ->
                  LocalClient.disconnect client
                )
            )
        )
    ) in
  run t

let test_10_connections () =
  let t = LocalServer.with_server (fun server ->
      PortsServer.with_server (fun ports_port ->
          ForwardControl.with_connection ports_port (fun connection ->
              let name = "tcp:127.0.0.1:0:" ^ LocalServer.to_string server in
              ForwardControl.with_forward connection name (fun ip port ->
                  let rec loop = function
                  | 0 -> Lwt.return ()
                  | n ->
                    LocalClient.connect (ip, port)
                    >>= fun client ->
                    http_get client
                    >>= fun () ->
                    LocalClient.disconnect client
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

let tests = [
  "Ports: 1 port forward",
  [ "Perform an HTTP GET through a port forward",
    `Quick,
    test_one_forward ];

  "Ports: 10 port forwards",
  [ "Perform 10 HTTP GETs through a port forward",
    `Quick,
    test_10_connections ];
]

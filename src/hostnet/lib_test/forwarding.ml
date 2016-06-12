open Hostnet
open Lwt.Infix

let src =
  let src = Logs.Src.create "test" ~doc:"Test the forwarding code" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let (>>*=) m f = m >>= function
  | Result.Ok x -> f x
  | Result.Error (`Msg m) -> failwith m


module Forward = Forward.Make(struct
  type port = Hostnet.Forward.Port.t

  include Hostnet.Conn_lwt_unix

  open Lwt.Infix

  let connect = function
    | `Tcp(ip, port) ->
      let sockaddr = Unix.ADDR_INET(Unix.inet_addr_of_string @@ Ipaddr.V4.to_string ip, port) in
      let fd = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_STREAM 0 in
      Lwt_unix.connect fd sockaddr
      >>= fun () ->
      Lwt.return (connect fd)
    | `Udp(_ip, _port) -> failwith "unimplemented"
end)(Hostnet.Port)

let ports_port = 1234

let localhost = Ipaddr.V4.(to_string localhost)

module PortsServer = struct
  module Ports = Active_list.Make(Forward)
  module Server = Server9p_unix.Make(Log)(Ports)

  let with_server f =
    let ports = Ports.make () in
    Ports.set_context ports "";
    Server.listen ports "tcp" (localhost ^ ":" ^ (string_of_int ports_port))
    >>*= fun server ->
    let _ = Server.serve_forever server in
    f ()
    >>= fun () ->
    Server.shutdown server
end

module LocalClient = struct
  let connect ip port =
    let fd = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_STREAM 0 in
    Lwt_unix.connect fd (Unix.ADDR_INET(Unix.inet_addr_of_string ip, port))
    >>= fun () ->
    Lwt.return fd
  let disconnect fd = Lwt_unix.close fd
end

module LocalServer = struct
  type t = {
    local_port: int;
    listening_socket: Lwt_unix.file_descr;
  }
  let create () =
    let listening_socket = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_STREAM 0 in
    Lwt_unix.setsockopt listening_socket Lwt_unix.SO_REUSEADDR true;
    Lwt_unix.bind listening_socket (Unix.ADDR_INET(Unix.inet_addr_of_string localhost, 0));
    let local_port = match Lwt_unix.getsockname listening_socket with
      | Lwt_unix.ADDR_INET(_, local_port) -> local_port
      | _ -> assert false in
    Lwt_unix.listen listening_socket 5;
    { local_port; listening_socket }
  let accept { listening_socket } =
    Lwt_unix.accept listening_socket
    >>= fun (fd, _) ->
    let server_ic = Lwt_io.of_fd ~close:Lwt.return ~mode:Lwt_io.input fd in
    let server_oc = Lwt_io.of_fd ~close:Lwt.return ~mode:Lwt_io.output fd in
    let rec read_request acc =
      Lwt_io.read_line server_ic
      >>= fun line ->
      if line = ""
      then Lwt.return acc
    else read_request (acc ^ line) in
    read_request ""
    >>= fun request ->
    if not(Astring.String.is_prefix ~affix:"GET" request)
    then failwith (Printf.sprintf "unrecognised HTTP GET: [%s]" request);
    let response = "HTTP/1.0 404 Not found\r\ncontent-length: 0\r\n\r\n" in
    Lwt_io.write server_oc response
    >>= fun () ->
    Lwt_io.flush server_oc
    >>= fun () ->
    Lwt_io.close server_oc
    >>= fun () ->
    Lwt_io.close server_ic
    >>= fun () ->
    Lwt_unix.close fd

  let to_string t =
    Printf.sprintf "tcp:%s:%d" localhost t.local_port
  let destroy t = Lwt_unix.close t.listening_socket
  let with_server f =
    let server = create () in
    Lwt.finalize
      (fun () ->
        f server
      ) (fun () ->
        destroy server
      )
end

module ForwardControl = struct
  module Log = (val Logs.src_log Logs.default)
  module Client = Client9p_unix.Make(Log)

  type t = {
    ninep: Client.t
  }

  let connect () =
    Client.connect "tcp" (localhost ^ ":" ^ (string_of_int ports_port)) ()
    >>*= fun ninep ->
    Lwt.return { ninep }

  let disconnect { ninep } = Client.disconnect ninep
  let with_connection f =
    connect ()
    >>= fun c ->
    Lwt.finalize (fun () -> f c) (fun () -> disconnect c)

  type forward = {
    t: t;
    fid: Protocol_9p_types.Fid.t;
    ip: string;
    port: int;
  }

  let create t string =
    let mode = Protocol_9p_types.FileMode.make ~is_directory:true
      ~owner:[`Read; `Write; `Execute] ~group:[`Read; `Execute]
      ~other:[`Read; `Execute ] () in
    Client.mkdir t.ninep [] string mode
    >>*= fun () ->
    Client.LowLevel.allocate_fid t.ninep
    >>*= fun fid ->
    Client.walk_from_root t.ninep fid [ string; "ctl" ]
    >>*= fun _walk ->
    Client.LowLevel.openfid t.ninep fid Protocol_9p_types.OpenMode.read_write
    >>*= fun _open ->
    let buf = Cstruct.create (String.length string) in
    Cstruct.blit_from_string string 0 buf 0 (String.length string);
    Client.LowLevel.write t.ninep fid 0L buf
    >>*= fun _write ->
    Client.LowLevel.read t.ninep fid 0L 1024l
    >>*= fun read ->
    let response = Cstruct.to_string read.Protocol_9p_response.Read.data in
    if Astring.String.is_prefix ~affix:"OK " response then begin
      let line = String.sub response 3 (String.length response - 3) in
      (* tcp:127.0.0.1:64500:tcp:127.0.0.1:64499 *)
      match Astring.String.cuts ~sep:":" line with
      | "tcp" :: ip :: port :: _ ->
        let port = int_of_string port in
        Lwt.return { t; fid; ip; port }
      | _ -> failwith ("failed to parse response: " ^ line)
    end else failwith response
  let destroy { t; fid } =
    Client.LowLevel.clunk t.ninep fid
    >>*= fun _clunk ->
    Lwt.return ()
  let with_forward t string f =
    create t string
    >>= fun forward ->
    Lwt.finalize (fun () -> f forward.ip forward.port) (fun () -> destroy forward)
end

let http_get client =
  let client_ic = Lwt_io.of_fd ~close:Lwt.return ~mode:Lwt_io.input client in
  let client_oc = Lwt_io.of_fd ~close:Lwt.return ~mode:Lwt_io.output client in
  let message = "GET / HTTP/1.0\r\nconnection: close\r\n\r\n" in
  Lwt_io.write client_oc message
  >>= fun () ->
  Lwt_io.flush client_oc
  >>= fun () ->
  Lwt_io.close client_oc
  >>= fun () ->
  Lwt_io.close client_ic

let test_one_forward () =
  let t =
    LocalServer.with_server
      (fun server ->
        PortsServer.with_server
          (fun () ->
            ForwardControl.with_connection
              (fun connection ->
                let name = "tcp:" ^ localhost ^ ":0:" ^ (LocalServer.to_string server) in
                ForwardControl.with_forward
                 connection
                  name
                  (fun ip port ->
                    let server = LocalServer.accept server in
                    LocalClient.connect ip port
                    >>= fun client ->
                    http_get client
                    >>= fun () ->
                    server 
                    >>= fun () ->
                    Lwt_unix.close client
                  )
              )
          )
      ) in
  Lwt_main.run t

let test_10_connections () =
  let t =
    LocalServer.with_server
      (fun server ->
        PortsServer.with_server
          (fun () ->
            ForwardControl.with_connection
              (fun connection ->
                let name = "tcp:" ^ localhost ^ ":0:" ^ (LocalServer.to_string server) in
                ForwardControl.with_forward
                 connection
                  name
                  (fun ip port ->
                    let rec loop = function
                      | 0 -> Lwt.return ()
                      | n ->
                        let server = LocalServer.accept server in
                        LocalClient.connect ip port
                        >>= fun client ->
                        http_get client
                        >>= fun () ->
                        server
                        >>= fun () ->
                        Lwt_unix.close client
                        >>= fun () ->
                        loop (n - 1) in
                    let start = Unix.gettimeofday () in
                    loop 10
                    >>= fun () ->
                    let time = Unix.gettimeofday () -. start in
                    (* NOTE(djs55): on my MBP this is almost immediate *)
                    if time > 1. then failwith (Printf.sprintf "10 connections took %.02f (> 1) seconds" time);
                    Lwt.return ()
                  )
              )
          )
      ) in
  Lwt_main.run t

let test = [
  "Test one port forward", `Quick, test_one_forward;
  "Check speed of 10 forwarded connections", `Quick, test_10_connections;
]

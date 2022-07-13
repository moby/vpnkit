let src =
  let src =
    Logs.Src.create "forwards" ~doc:"Forwards TCP/UDP streams to local services"
  in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Protocol = struct
  type t = [ `Tcp ]
  (* consider UDP later *)

  open Ezjsonm

  let to_json t = string (match t with `Tcp -> "tcp")

  let of_json j =
    match get_string j with
    | "tcp" -> `Tcp
    | _ -> raise (Parse_error (j, "protocol should be tcp"))
end

type forward = {
  protocol : Protocol.t;
  dst_prefix : Ipaddr.Prefix.t;
  dst_port : int;
  path : string; (* unix domain socket path *)
}

let forward_to_json t =
  let open Ezjsonm in
  dict
    [
      ("protocol", Protocol.to_json t.protocol);
      ("dst_prefix", string (Ipaddr.Prefix.to_string t.dst_prefix));
      ("dst_port", int t.dst_port);
      ("path", string t.path);
    ]

let forward_of_json j =
  let open Ezjsonm in
  let protocol = Protocol.of_json @@ find j [ "protocol" ] in
  let dst_port = get_int @@ find j [ "dst_port" ] in
  let path = get_string @@ find j [ "path" ] in
  let dst_prefix =
    match Ipaddr.Prefix.of_string @@ get_string @@ find j [ "dst_prefix" ] with
    | Error (`Msg m) ->
        raise (Parse_error (j, "dst_ip should be an IP prefix: " ^ m))
    | Ok x -> x
  in
  { protocol; dst_prefix; dst_port; path }

type t = forward list

let to_json = Ezjsonm.list forward_to_json
let of_json = Ezjsonm.get_list forward_of_json
let to_string x = Ezjsonm.to_string @@ to_json x

let of_string x =
  try Ok (of_json @@ Ezjsonm.from_string x) with
  | Ezjsonm.Parse_error (_v, msg) -> Error (`Msg msg)
  | e -> Error (`Msg (Printf.sprintf "parsing %s: %s" x (Printexc.to_string e)))

let dynamic = ref []
let static = ref []
let all = ref []

let set_static xs =
  static := xs;
  all := !static @ !dynamic;
  Log.info (fun f -> f "New Forward configuration: %s" (to_string !all))

let update xs =
  dynamic := xs;
  all := !static @ !dynamic;
  Log.info (fun f -> f "New Forward configuration: %s" (to_string !all))

(* Extend a SHUTDOWNABLE flow with a `read_some` API, as used by "channel".
   Ideally we would use channel, but we need to access the underlying flow
   without leaving data trapped in the buffer. *)
module type Read_some = sig
  include Mirage_flow_combinators.SHUTDOWNABLE

  val read_some :
    flow -> int -> (Cstructs.t Mirage_flow.or_eof, error) result Lwt.t
end

module Read_some (FLOW : Mirage_flow_combinators.SHUTDOWNABLE) : sig
  include Read_some

  val connect : FLOW.flow -> flow
end = struct
  (* A flow with a buffer, filled by "read_some" and then drained by "read" *)
  type flow = { mutable remaining : Cstruct.t; flow : FLOW.flow }

  let connect flow = { remaining = Cstruct.create 0; flow }

  type error = FLOW.error

  let pp_error = FLOW.pp_error

  type write_error = FLOW.write_error

  let pp_write_error = FLOW.pp_write_error

  let read_some flow len =
    let open Lwt.Infix in
    let rec loop acc len =
      if Cstruct.length flow.remaining = 0 && len > 0 then
        FLOW.read flow.flow >>= function
        | Error e -> Lwt.return (Error e)
        | Ok (`Data buf) ->
            flow.remaining <- buf;
            loop acc len
        | Ok `Eof -> Lwt.return (Ok `Eof)
      else if Cstruct.length flow.remaining < len then (
        let take = flow.remaining in
        flow.remaining <- Cstruct.create 0;
        loop (take :: acc) (len - Cstruct.length take))
      else
        let take, leave = Cstruct.split flow.remaining len in
        flow.remaining <- leave;
        Lwt.return @@ Ok (`Data (List.rev (take :: acc)))
    in
    loop [] len

  let read flow =
    if Cstruct.length flow.remaining > 0 then (
      let result = flow.remaining in
      flow.remaining <- Cstruct.create 0;
      Lwt.return @@ Ok (`Data result))
    else FLOW.read flow.flow

  let write flow = FLOW.write flow.flow
  let writev flow = FLOW.writev flow.flow
  let close flow = FLOW.close flow.flow
  let shutdown_write flow = FLOW.shutdown_write flow.flow
  let shutdown_read flow = FLOW.shutdown_read flow.flow
end

module Handshake (FLOW : Read_some) = struct
  (* A Message is a buffer prefixed with a uint16 length field. *)
  module Message = struct
    open Lwt.Infix

    let pp_error ppf = function
      | `Flow e -> FLOW.pp_error ppf e
      | `Eof -> Fmt.string ppf "EOF while reading handshake"

    let read flow =
      FLOW.read_some flow 2 >>= function
      | Error e -> Lwt.return (Error (`Flow e))
      | Ok `Eof -> Lwt.return (Error `Eof)
      | Ok (`Data bufs) -> (
          let buf = Cstructs.to_cstruct bufs in
          let len = Cstruct.LE.get_uint16 buf 0 in
          FLOW.read_some flow len >>= function
          | Error e -> Lwt.return (Error (`Flow e))
          | Ok `Eof -> Lwt.return (Error `Eof)
          | Ok (`Data bufs) -> Lwt.return (Ok (Cstructs.to_cstruct bufs)))

    let write flow t =
      let len = Cstruct.create 2 in
      Cstruct.LE.set_uint16 len 0 (Cstruct.length t);
      FLOW.writev flow [ len; t ]
  end

  module Request = struct
    type t = {
      protocol : Protocol.t;
      src_ip : Ipaddr.t;
      src_port : int;
      dst_ip : Ipaddr.t;
      dst_port : int;
    }

    open Ezjsonm

    let of_json j =
      let protocol = Protocol.of_json @@ find j [ "protocol" ] in
      let src_ip =
        match Ipaddr.of_string @@ get_string @@ find j [ "src_ip" ] with
        | Error (`Msg m) ->
            raise (Parse_error (j, "src_ip should be an IP address: " ^ m))
        | Ok x -> x
      in
      let src_port = get_int @@ find j [ "src_port" ] in
      let dst_ip =
        match Ipaddr.of_string @@ get_string @@ find j [ "dst_ip" ] with
        | Error (`Msg m) ->
            raise (Parse_error (j, "dst_ip should be an IP address: " ^ m))
        | Ok x -> x
      in
      let dst_port = get_int @@ find j [ "dst_port" ] in
      { protocol; src_ip; src_port; dst_ip; dst_port }

    let to_json t =
      let open Ezjsonm in
      dict
        [
          ("protocol", Protocol.to_json t.protocol);
          ("src_ip", string (Ipaddr.to_string t.src_ip));
          ("src_port", int t.src_port);
          ("dst_ip", string (Ipaddr.to_string t.dst_ip));
          ("dst_port", int t.dst_port);
        ]

    let to_string t = Ezjsonm.to_string @@ to_json t

    open Lwt.Infix

    let read flow =
      Message.read flow >>= function
      | Error (`Flow e) -> Lwt.return (Error (`Flow e))
      | Error `Eof -> Lwt.return (Error `Eof)
      | Ok buf ->
          let j = Ezjsonm.from_string @@ Cstruct.to_string buf in
          Lwt.return (Ok (of_json j))

    let write flow t =
      Message.write flow @@ Cstruct.of_string @@ Ezjsonm.to_string @@ to_json t
  end

  module Response = struct
    type t = { accepted : bool }

    open Ezjsonm

    let of_json j =
      let accepted = get_bool @@ find j [ "accepted" ] in
      { accepted }

    let to_json t =
      let open Ezjsonm in
      dict [ ("accepted", bool t.accepted) ]

    open Lwt.Infix

    let read flow =
      Message.read flow >>= function
      | Error (`Flow e) -> Lwt.return (Error (`Flow e))
      | Error `Eof -> Lwt.return (Error `Eof)
      | Ok buf ->
          let j = Ezjsonm.from_string @@ Cstruct.to_string buf in
          Lwt.return (Ok (of_json j))

    let write flow t =
      Message.write flow @@ Cstruct.of_string @@ Ezjsonm.to_string @@ to_json t
  end
end

module Tcp = struct
  let any_port = 0

  let mem (dst_ip, dst_port) =
    List.exists
      (fun f ->
        f.protocol = `Tcp
        && Ipaddr.Prefix.mem dst_ip f.dst_prefix
        && (f.dst_port = any_port || f.dst_port = dst_port))
      !all

  let find (dst_ip, dst_port) =
    let f =
      List.find
        (fun f ->
          f.protocol = `Tcp
          && Ipaddr.Prefix.mem dst_ip f.dst_prefix
          && (f.dst_port = any_port || f.dst_port = dst_port))
        !all
    in
    f.path
end

module Unix = struct
  module FLOW = Host.Sockets.Stream.Unix
  module Remote = Read_some (FLOW)
  module Handshake = Handshake (Remote)

  type flow = { flow : Remote.flow }

  let connect ?read_buffer_size:_ (dst_ip, dst_port) =
    let open Lwt.Infix in
    let path = Tcp.find (dst_ip, dst_port) in
    let req = Fmt.str "%a, %d -> %s" Ipaddr.pp dst_ip dst_port path in
    Log.info (fun f -> f "%s: connecting" req);
    FLOW.connect path >>= function
    | Error (`Msg m) -> Lwt.return (Error (`Msg m))
    | Ok flow -> (
        Log.info (fun f -> f "%s: writing handshake" req);
        let remote = Remote.connect flow in
        Handshake.Request.write remote
          {
            Handshake.Request.protocol = `Tcp;
            src_ip = Ipaddr.V4 Ipaddr.V4.any;
            src_port = 0;
            dst_ip;
            dst_port;
          }
        >>= function
        | Error e ->
            Log.info (fun f ->
                f "%s: %a, returning RST" req Remote.pp_write_error e);
            Remote.close remote >>= fun () ->
            Lwt.return
              (Error
                 (`Msg
                   (Fmt.str "writing handshake: %a" Remote.pp_write_error e)))
        | Ok () -> (
            Log.info (fun f -> f "%s: reading handshake" req);
            Handshake.Response.read remote >>= function
            | Error e ->
                Log.info (fun f ->
                    f "%s: %a, returning RST" req Handshake.Message.pp_error e);
                Remote.close remote >>= fun () ->
                Lwt.return
                  (Error
                     (`Msg
                       (Fmt.str "reading handshake: %a"
                          Handshake.Message.pp_error e)))
            | Ok { Handshake.Response.accepted = false } ->
                Log.info (fun f -> f "%s: request rejected" req);
                Remote.close remote >>= fun () ->
                Lwt.return (Error (`Msg "ECONNREFUSED"))
            | Ok { Handshake.Response.accepted = true } ->
                Log.info (fun f -> f "%s: forwarding connection" req);
                Lwt.return (Ok { flow = remote })))

  type error = Remote.error

  let pp_error = Remote.pp_error

  type write_error = Remote.write_error

  let pp_write_error = Remote.pp_write_error
  let read flow = Remote.read flow.flow
  let write flow = Remote.write flow.flow
  let writev flow = Remote.writev flow.flow
  let close flow = Remote.close flow.flow
  let shutdown_write flow = Remote.shutdown_write flow.flow
  let shutdown_read flow = Remote.shutdown_read flow.flow
end

module Stream = struct
  module Tcp = struct
    type address = Ipaddr.t * int

    module Direct = Host.Sockets.Stream.Tcp
    module Forwarded = Unix

    type flow = [ `Direct of Direct.flow | `Forwarded of Forwarded.flow ]

    open Lwt.Infix

    let connect ?read_buffer_size:_ (ip, port) =
      if Tcp.mem (ip, port) then
        Unix.connect (ip, port) >>= function
        | Ok flow -> Lwt.return (Ok (`Forwarded flow))
        | Error e -> Lwt.return (Error e)
      else
        Direct.connect (ip, port) >>= function
        | Ok flow -> Lwt.return (Ok (`Direct flow))
        | Error e -> Lwt.return (Error e)

    type error = [ `Direct of Direct.error | `Forwarded of Forwarded.error ]

    let pp_error ppf = function
      | `Direct err -> Direct.pp_error ppf err
      | `Forwarded err -> Forwarded.pp_error ppf err

    type write_error =
      [ `Closed
      | `Direct of Direct.write_error
      | `Forwarded of Forwarded.write_error ]

    let pp_write_error ppf = function
      | `Closed -> Fmt.string ppf "Closed"
      | `Direct err -> Direct.pp_write_error ppf err
      | `Forwarded err -> Forwarded.pp_write_error ppf err

    let wrap_direct_error t =
      t >>= function
      | Ok x -> Lwt.return (Ok x)
      | Error err -> Lwt.return (Error (`Direct err))

    let wrap_forwarded_error t =
      t >>= function
      | Ok x -> Lwt.return (Ok x)
      | Error err -> Lwt.return (Error (`Forwarded err))

    let read = function
      | `Direct flow -> wrap_direct_error @@ Direct.read flow
      | `Forwarded flow -> wrap_forwarded_error @@ Forwarded.read flow

    let write flow bufs =
      match flow with
      | `Direct flow -> wrap_direct_error @@ Direct.write flow bufs
      | `Forwarded flow -> wrap_forwarded_error @@ Forwarded.write flow bufs

    let writev flow bufs =
      match flow with
      | `Direct flow -> wrap_direct_error @@ Direct.writev flow bufs
      | `Forwarded flow -> wrap_forwarded_error @@ Forwarded.writev flow bufs

    let close = function
      | `Direct flow -> Direct.close flow
      | `Forwarded flow -> Forwarded.close flow

    let shutdown_write = function
      | `Direct flow -> Direct.shutdown_write flow
      | `Forwarded flow -> Forwarded.shutdown_write flow

    let shutdown_read = function
      | `Direct flow -> Direct.shutdown_read flow
      | `Forwarded flow -> Forwarded.shutdown_read flow
  end
end

module Test (Clock : Mirage_clock.MCLOCK) = struct
  module Remote = Read_some (Host.Sockets.Stream.Unix)

  module Proxy =
    Mirage_flow_combinators.Proxy (Clock) (Remote) (Host.Sockets.Stream.Tcp)

  module Handshake = Handshake (Remote)
  open Lwt.Infix

  type server = Host.Sockets.Stream.Unix.server

  let start_forwarder path =
    Host.Sockets.Stream.Unix.bind path >>= fun s ->
    Host.Sockets.Stream.Unix.listen s (fun flow ->
        Log.info (fun f -> f "accepted flow");
        let local = Remote.connect flow in
        Handshake.Request.read local >>= function
        | Error e ->
            Log.info (fun f ->
                f "reading handshake request %a" Handshake.Message.pp_error e);
            Lwt.return_unit
        | Ok h -> (
            let req = Handshake.Request.to_string h in
            Log.info (fun f -> f "%s: connecting" req);
            Host.Sockets.Stream.Tcp.connect
              (h.Handshake.Request.dst_ip, h.Handshake.Request.dst_port)
            >>= function
            | Error (`Msg m) -> (
                Log.info (fun f -> f "%s: %s" req m);
                Handshake.Response.write local
                  { Handshake.Response.accepted = false }
                >>= function
                | Error e ->
                    Log.info (fun f ->
                        f "%s: writing handshake response %a" req
                          Remote.pp_write_error e);
                    Lwt.return_unit
                | Ok () ->
                    Log.info (fun f -> f "%s: returned handshake response" req);
                    Lwt.return_unit)
            | Ok remote ->
                Log.info (fun f -> f "%s: connected" req);
                Lwt.finalize
                  (fun () ->
                    Handshake.Response.write local
                      { Handshake.Response.accepted = true }
                    >>= function
                    | Error e ->
                        Log.info (fun f ->
                            f "%s: writing handshake response %a" req
                              Remote.pp_write_error e);
                        Lwt.return_unit
                    | Ok () -> (
                        Log.info (fun f -> f "%s: proxying data" req);
                        Proxy.proxy local remote >>= function
                        | Error e ->
                            Log.info (fun f ->
                                f "%s: TCP proxy failed with %a" req
                                  Proxy.pp_error e);
                            Lwt.return_unit
                        | Ok (_l_stats, _r_stats) -> Lwt.return_unit))
                  (fun () ->
                    Log.info (fun f -> f "%s: disconnecting from remote" req);
                    Host.Sockets.Stream.Tcp.close remote)));
    Lwt.return s

  let shutdown = Host.Sockets.Stream.Unix.shutdown
end

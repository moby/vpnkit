(*
 * Copyright (C) 2016 David Scott <dave@recoil.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)
open Lwt.Infix

let src =
  let src = Logs.Src.create "Dns_forward_lwt_unix" ~doc:"Lwt_unix-based I/O" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let default_read_buffer_size = 65536
let max_udp_length = 65507 (* IP datagram (65535) - IP header(20) - UDP header(8) *)

let string_of_sockaddr = function
| Lwt_unix.ADDR_INET(ip, port) -> Unix.string_of_inet_addr ip ^ ":" ^ (string_of_int port)
| Lwt_unix.ADDR_UNIX path -> path

module Common = struct
  (** Both UDP and TCP *)

  type error = [ `Msg of string ]
  type write_error = Mirage_flow.write_error
  let pp_error ppf (`Msg x) = Fmt.string ppf x
  let pp_write_error = Mirage_flow.pp_write_error
  let errorf fmt = Printf.ksprintf (fun s -> Lwt.return (Error (`Msg s))) fmt

  type address = Ipaddr.t * int

  let sockaddr_of_address (dst, dst_port) =
    Unix.ADDR_INET(Unix.inet_addr_of_string @@ Ipaddr.to_string dst, dst_port)

  let address_of_sockaddr = function
  | Lwt_unix .ADDR_INET(ip, port) ->
      ( try Some (Ipaddr.of_string_exn @@ Unix.string_of_inet_addr ip, port) with _ -> None )
  | _ -> None

  let string_of_address (dst, dst_port) =
    Ipaddr.to_string dst ^ ":" ^ (string_of_int dst_port)

  let getsockname fn_name fd_opt = match fd_opt with
  | None -> failwith (fn_name ^ ": socket is closed")
  | Some fd ->
      begin match Lwt_unix.getsockname fd with
      | Lwt_unix.ADDR_INET(iaddr, port) ->
          Ipaddr.V4 (Ipaddr.V4.of_string_exn (Unix.string_of_inet_addr iaddr)), port
      | _ -> invalid_arg (fn_name ^ ": passed a non-TCP socket")
      end
end

module Tcp = struct
  include Common

  type flow = {
    mutable fd: Lwt_unix.file_descr option;
    read_buffer_size: int;
    mutable read_buffer: Cstruct.t;
    address: address;
  }

  let of_fd ~read_buffer_size address fd =
    let read_buffer = Cstruct.create read_buffer_size in
    { fd = Some fd; read_buffer_size; read_buffer; address }

  let string_of_flow flow =
    Printf.sprintf "tcp -> %s" (string_of_address flow.address)

  let connect ?(read_buffer_size=default_read_buffer_size) address =
    let description = Printf.sprintf "tcp -> %s" (string_of_address address) in
    Log.debug (fun f -> f "%s: connect" description);

    let sockaddr = sockaddr_of_address address in
    let fd = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_STREAM 0 in
    Lwt.catch
      (fun () ->
         Lwt_unix.connect fd sockaddr
         >>= fun () ->
         Lwt.return (Ok (of_fd ~read_buffer_size address fd))
      )
      (fun e ->
         Lwt_unix.close fd
         >>= fun () ->
         errorf "%s: Lwt_unix.connect: caught %s" description (Printexc.to_string e)
      )

  let read t = match t.fd with
  | None -> Lwt.return (Ok `Eof)
  | Some fd ->
      if Cstruct.len t.read_buffer = 0 then t.read_buffer <- Cstruct.create t.read_buffer_size;
      Lwt.catch
        (fun () ->
           Lwt_bytes.read fd t.read_buffer.Cstruct.buffer t.read_buffer.Cstruct.off t.read_buffer.Cstruct.len
           >>= function
           | 0 -> Lwt.return (Ok `Eof)
           | n ->
               let results = Cstruct.sub t.read_buffer 0 n in
               t.read_buffer <- Cstruct.shift t.read_buffer n;
               Lwt.return (Ok (`Data results))
        ) (fun e ->
            Log.err (fun f -> f "%s: read caught %s returning Eof"
                        (string_of_flow t)
                        (Printexc.to_string e)
                    );
            Lwt.return (Ok `Eof)
          )

  let write t buf = match t.fd with
  | None -> Lwt.return (Error `Closed)
  | Some fd ->
      Lwt.catch
        (fun () ->
           Lwt_cstruct.(complete (write fd) buf)
           >>= fun () ->
           Lwt.return (Ok ())
        ) (function
          | Unix.Unix_error(Unix.ECONNRESET, _, _) -> Lwt.return (Error `Closed)
          | e ->
              Log.err (fun f -> f "%s: write caught %s returning Eof"
                          (string_of_flow t)
                          (Printexc.to_string e)
                      );
              Lwt.return (Error `Closed)
          )

  let writev t bufs = match t.fd with
  | None -> Lwt.return (Error `Closed)
  | Some fd ->
      Lwt.catch
        (fun () ->
           let rec loop = function
           | [] -> Lwt.return (Ok ())
           | buf :: bufs ->
               Lwt_cstruct.(complete (write fd) buf)
               >>= fun () ->
               loop bufs in
           loop bufs
        ) (fun _e ->
            Lwt.return (Error `Closed)
          )

  let close t = match t.fd with
  | None -> Lwt.return_unit
  | Some fd ->
      t.fd <- None;
      Log.debug (fun f -> f "%s: Tcp.close" (string_of_flow t));
      Lwt_unix.close fd

  let shutdown_read t = match t.fd with
  | None -> Lwt.return_unit
  | Some fd ->
      Lwt.catch
        (fun () ->
           Lwt_unix.shutdown fd Unix.SHUTDOWN_RECEIVE;
           Lwt.return_unit
        ) (function
          | Unix.Unix_error(Unix.ENOTCONN, _, _) -> Lwt.return_unit
          | e ->
              Log.err (fun f -> f "%s: Lwt_unix.shutdown receive caught %s"
                          (string_of_flow t)
                          (Printexc.to_string e)
                      );
              Lwt.return_unit
          )

  let shutdown_write t = match t.fd with
  | None -> Lwt.return_unit
  | Some fd ->
      Lwt.catch
        (fun () ->
           Lwt_unix.shutdown fd Unix.SHUTDOWN_SEND;
           Lwt.return_unit
        ) (function
          | Unix.Unix_error(Unix.ENOTCONN, _, _) -> Lwt.return_unit
          | e ->
              Log.err (fun f -> f "%s: Lwt_unix.shutdown send caught %s"
                          (string_of_flow t)
                          (Printexc.to_string e)
                      );
              Lwt.return_unit
          )

  type server = {
    mutable server_fd: Lwt_unix.file_descr option;
    read_buffer_size: int;
    address: address;
  }

  let string_of_server t =
    Printf.sprintf "listen:tcp <- %s" (string_of_address t.address)

  let bind address =
    let fd = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_STREAM 0 in
    Lwt.catch
      (fun () ->
         Lwt_unix.setsockopt fd Lwt_unix.SO_REUSEADDR true;
         Lwt_unix.bind fd (sockaddr_of_address address) >|= fun () ->
         Ok { server_fd = Some fd;
              read_buffer_size = default_read_buffer_size;
              address }
      ) (fun e ->
          Lwt_unix.close fd
          >>= fun () ->
          errorf "listen:tcp <- %s caught %s"
            (string_of_address address)
            (Printexc.to_string e)
        )

  let getsockname server = getsockname "Tcp.getsockname" server.server_fd

  let shutdown server = match server.server_fd with
  | None -> Lwt.return_unit
  | Some fd ->
      server.server_fd <- None;
      Log.debug (fun f -> f "%s: close server socket" (string_of_server server));
      Lwt_unix.close fd

  let listen (server: server) cb =
    let rec loop fd =
      Lwt_unix.accept fd
      >>= fun (client, sockaddr) ->
      let read_buffer_size = server.read_buffer_size in

      Lwt.async
        (fun () ->
           Lwt.catch
             (fun () ->
                ( match address_of_sockaddr sockaddr with
                | Some address ->
                    Lwt.return address
                | _ ->
                    Lwt.fail (Failure "unknown incoming socket address")
                ) >>= fun address ->
                Lwt.return (Some (of_fd ~read_buffer_size address client))
             ) (fun _e ->
                 Lwt_unix.close client
                 >>= fun () ->
                 Lwt.return_none
               )
           >>= function
           | None -> Lwt.return_unit
           | Some flow ->
               Lwt.finalize
                 (fun () ->
                    Lwt.catch
                      (fun () -> cb flow)
                      (fun e ->
                         Log.info (fun f -> f "tcp:%s <- %s: caught %s so closing flow"
                                      (string_of_server server)
                                      (string_of_sockaddr sockaddr)
                                      (Printexc.to_string e)
                                  );
                         Lwt.return_unit)
                 ) (fun () -> close flow)
        );
      loop fd in
    match server.server_fd with
    | None -> ()
    | Some fd ->
        Lwt.async
          (fun () ->
             Lwt.catch
               (fun () ->
                  Lwt.finalize
                    (fun () ->
                       Lwt_unix.listen fd 32;
                       loop fd
                    ) (fun () ->
                        shutdown server
                      )
               ) (fun e ->
                   Log.info (fun f -> f "%s: caught %s so shutting down server"
                                (string_of_server server)
                                (Printexc.to_string e)
                            );
                   Lwt.return_unit
                 )
          )
end

module Udp = struct

  include Common

  type flow = {
    mutable fd: Lwt_unix.file_descr option;
    read_buffer_size: int;
    mutable already_read: Cstruct.t option;
    sockaddr: Unix.sockaddr;
    address: address;
  }

  let string_of_flow t = Printf.sprintf "udp -> %s" (string_of_address t.address)

  let of_fd ?(read_buffer_size = max_udp_length) ?(already_read = None) sockaddr address fd =
    { fd = Some fd; read_buffer_size; already_read; sockaddr; address }

  let connect ?read_buffer_size address =
    Log.debug (fun f -> f "udp -> %s: connect" (string_of_address address));

    let fd = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_DGRAM 0 in
    (* Win32 requires all sockets to be bound however macOS and Linux don't *)
    Lwt.catch (fun () ->
        Lwt_unix.bind fd (Lwt_unix.ADDR_INET(Unix.inet_addr_any, 0))
      ) (fun _ -> Lwt.return ())
    >|= fun () ->
    let sockaddr = sockaddr_of_address address in
    Ok (of_fd ?read_buffer_size sockaddr address fd)

  let read t = match t.fd, t.already_read with
  | None, _ -> Lwt.return (Ok `Eof)
  | Some _, Some data when Cstruct.len data > 0 ->
      t.already_read <- Some (Cstruct.sub data 0 0); (* next read is `Eof *)
      Lwt.return (Ok (`Data data))
  | Some _, Some _ ->
      Lwt.return (Ok `Eof)
  | Some fd, None ->
      let buffer = Cstruct.create t.read_buffer_size in
      let bytes = Bytes.make t.read_buffer_size '\000' in
      Lwt.catch
        (fun () ->
           (* Lwt on Win32 doesn't support Lwt_bytes.recvfrom *)
           Lwt_unix.recvfrom fd bytes 0 (Bytes.length bytes) []
           >>= fun (n, _) ->
           Cstruct.blit_from_bytes bytes 0 buffer 0 n;
           let response = Cstruct.sub buffer 0 n in
           Lwt.return (Ok (`Data response))
        ) (fun e ->
            Log.err (fun f -> f "%s: recvfrom caught %s returning Eof"
                        (string_of_flow t)
                        (Printexc.to_string e)
                    );
            Lwt.return (Ok `Eof)
          )

  let write t buf = match t.fd with
  | None -> Lwt.return (Error `Closed)
  | Some fd ->
      Lwt.catch
        (fun () ->
           (* Lwt on Win32 doesn't support Lwt_bytes.sendto *)
           let bytes = Bytes.make (Cstruct.len buf) '\000' in
           Cstruct.blit_to_bytes buf 0 bytes 0 (Cstruct.len buf);
           Lwt_unix.sendto fd bytes 0 (Bytes.length bytes) [] t.sockaddr
           >|= fun _n -> Ok ()
        ) (fun e ->
            Log.err (fun f -> f "%s: sendto caught %s returning Eof"
                        (string_of_flow t)
                        (Printexc.to_string e)
                    );
            Lwt.return (Error `Closed)
          )

  let writev t bufs = write t (Cstruct.concat bufs)

  let close t = match t.fd with
  | None -> Lwt.return_unit
  | Some fd ->
      t.fd <- None;
      Log.debug (fun f -> f "%s: close" (string_of_flow t));
      Lwt_unix.close fd

  let shutdown_read _t = Lwt.return_unit
  let shutdown_write _t = Lwt.return_unit

  type server = {
    mutable server_fd: Lwt_unix.file_descr option;
    address: address;
  }

  let string_of_server t =
    Printf.sprintf "listen udp:%s" (string_of_address t.address)

  let getsockname server = getsockname "Udp.getsockname" server.server_fd

  let bind address =
    let fd = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_DGRAM 0 in
    try
      let sockaddr = sockaddr_of_address address in
      Lwt_unix.bind fd sockaddr >|= fun () ->
      Ok { server_fd = Some fd; address }
    with
    | e -> errorf "udp:%s: bind caught %s"
             (string_of_address address) (Printexc.to_string e)

  let shutdown t = match t.server_fd with
  | None -> Lwt.return_unit
  | Some fd ->
      t.server_fd <- None;
      Log.debug (fun f -> f "%s: close" (string_of_server t));
      Lwt_unix.close fd

  let listen t flow_cb =
    let buffer = Cstruct.create max_udp_length in
    let bytes = Bytes.make max_udp_length '\000' in
    match t.server_fd with
    | None -> ()
    | Some fd ->
        let rec loop () =
          Lwt.catch
            (fun () ->
               (* Lwt on Win32 doesn't support Lwt_bytes.recvfrom *)
               Lwt_unix.recvfrom fd bytes 0 (Bytes.length bytes) []
               >>= fun (n, sockaddr) ->
               Cstruct.blit_from_bytes bytes 0 buffer 0 n;
               let data = Cstruct.sub buffer 0 n in
               (* construct a flow with this buffer available for reading *)
               ( match address_of_sockaddr sockaddr with
               | Some address -> Lwt.return address
               | None -> Lwt.fail (Failure "failed to discover incoming socket address")
               ) >>= fun address ->
               let flow = of_fd ~read_buffer_size:0 ~already_read:(Some data) sockaddr address fd in
               Lwt.async
                 (fun () ->
                    Lwt.catch
                      (fun () -> flow_cb flow)
                      (fun e ->
                         Log.info (fun f -> f "%s: listen callback caught: %s"
                                      (string_of_server t)
                                      (Printexc.to_string e)
                                  );
                         Lwt.return_unit
                      )
                 );
               Lwt.return true
            ) (fun e ->
                Log.err (fun f -> f "%s: listen caught %s shutting down server"
                            (string_of_server t)
                            (Printexc.to_string e)
                        );
                Lwt.return false
              )
          >>= function
          | false -> Lwt.return_unit
          | true -> loop () in
        Lwt.async loop
end

module Time = struct
  let sleep_ns ns = Lwt_unix.sleep (Duration.to_f ns)
end
module Clock = Mclock

module R = struct
  open Dns_forward
  module Udp_client = Rpc.Client.Nonpersistent.Make(Udp)(Framing.Udp(Udp))(Time)
  module Udp = Resolver.Make(Udp_client)(Time)(Clock)

  module Tcp_client = Rpc.Client.Persistent.Make(Tcp)(Framing.Tcp(Tcp))(Time)
  module Tcp = Resolver.Make(Tcp_client)(Time)(Clock)
end

module Server = struct
  open Dns_forward
  module Udp_server = Rpc.Server.Make(Udp)(Framing.Udp(Udp))(Time)
  module Udp = Server.Make(Udp_server)(R.Udp)

  module Tcp_server = Rpc.Server.Make(Tcp)(Framing.Tcp(Tcp))(Time)
  module Tcp = Server.Make(Tcp_server)(R.Tcp)
end

module Resolver = R

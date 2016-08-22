let src =
  let src = Logs.Src.create "port forward" ~doc:"forward local ports to the VM" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

open Lwt.Infix
open Hostnet
open Vmnet

let error_of_failure f = Lwt.catch f (fun e -> Lwt.return (`Error (`Msg (Printexc.to_string e))))

let is_windows = Sys.os_type = "Win32"

module Make(Socket: Sig.SOCKETS) = struct

  module Channel = Channel.Make(Socket.Stream.Unix)

  type t = {
    fd: Socket.Stream.Unix.flow;
    c: Channel.t;
  }

  let register_connection = Socket.register_connection
  let deregister_connection = Socket.deregister_connection
  let set_max_connections = Socket.set_max_connections
  let dump_connection_table = Socket.dump_connection_table

  module Infix = struct
    let ( >>= ) m f = m >>= function
      | `Ok x -> f x
      | `Error x -> Lwt.return (`Error x)
  end

  let of_fd fd =
    let buf = Cstruct.create Init.sizeof in
    let (_: Cstruct.t) = Init.marshal Init.default buf in
    error_of_failure
      (fun () ->
         let c = Channel.create fd in
         Channel.write_buffer c buf;
         Channel.flush c
         >>= fun () ->
         Channel.read_exactly ~len:Init.sizeof c
         >>= fun bufs ->
         let buf = Cstruct.concat bufs in
         let open Infix in
         Lwt.return (Init.unmarshal buf)
         >>= fun (init, _) ->
         Log.info (fun f -> f "Client.negotiate: received %s" (Init.to_string init));
         Lwt.return (`Ok { fd; c })
      )

  let bind_ipv4 t (ipv4, port, stream) =
    let buf = Cstruct.create Command.sizeof in
    let (_: Cstruct.t) = Command.marshal (Command.Bind_ipv4(ipv4, port, stream)) buf in
    Channel.write_buffer t.c buf;
    Channel.flush t.c
    >>= fun () ->
    let rawfd = Socket.Stream.Unix.unsafe_get_raw_fd t.fd in
    let result = String.make 8 '\000' in
    let n, _, fd = Fd_send_recv.recv_fd rawfd result 0 8 [] in

    ( if n <> 8 then Lwt.return (`Error (`Msg (Printf.sprintf "Message only contained %d bytes" n))) else begin
        let buf = Cstruct.create 8 in
        Cstruct.blit_from_string result 0 buf 0 8;
        Log.debug (fun f ->
            let b = Buffer.create 16 in
            Cstruct.hexdump_to_buffer b buf;
            f "received result bytes: %s which is %s" (String.escaped result) (Buffer.contents b)
          );
        match Cstruct.LE.get_uint64 buf 0 with
        | 0L -> Lwt.return (`Ok fd)
        | n ->
          begin match n with
            | 48L -> Lwt.return (`Error (`Msg "EADDRINUSE"))
            | 49L -> Lwt.return (`Error (`Msg "EADDRNOTAVAIL"))
            | n   ->
              Lwt.return (`Error (`Msg ("Failed to bind: unrecognised errno: " ^ (Int64.to_string n))))
          end
      end )
    >>= function
    | `Error x ->
      Unix.close fd;
      Lwt.return (`Error x)
    | `Ok x ->
      Lwt.return (`Ok x)

  (* This implementation is OSX-only *)
  let request_privileged_port local_ip local_port sock_stream =
    let open Infix in
    Socket.Stream.Unix.connect "/var/tmp/com.docker.vmnetd.socket"
    >>= fun flow ->
    Lwt.finalize
      (fun () ->
         of_fd flow
         >>= fun c ->
         bind_ipv4 c (local_ip, local_port, sock_stream)
      ) (fun () -> Socket.Stream.Unix.close flow)

  module Datagram = struct
    type address = Socket.Datagram.address
    type reply = Socket.Datagram.reply

    let input = Socket.Datagram.input
    let get_nat_table_size = Socket.Datagram.get_nat_table_size

    module Udp = struct
      include Socket.Datagram.Udp

      let bind (local_ip, local_port) =
        match local_ip with
        | Ipaddr.V4 ipv4 ->
          if local_port < 1024 && not is_windows then begin
            request_privileged_port ipv4 local_port false
            >>= function
            | `Error (`Msg x) -> Lwt.fail (Failure x)
            | `Ok fd ->
              Lwt.return (Socket.Datagram.Udp.of_bound_fd fd)
          end else bind (local_ip, local_port)
        | _ -> bind (local_ip, local_port)
    end
  end

  module Stream = struct
    module Tcp = struct
      include Socket.Stream.Tcp

      let bind (local_ip, local_port) =
        if local_port < 1024 && not is_windows then begin
          request_privileged_port local_ip local_port true
          >>= function
          | `Error (`Msg x) -> Lwt.fail (Failure x)
          | `Ok fd ->
            Lwt.return (Socket.Stream.Tcp.of_bound_fd fd)
        end else bind (local_ip, local_port)
    end

    module Unix = Socket.Stream.Unix
  end
end

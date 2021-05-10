let src =
  let src = Logs.Src.create "port forward" ~doc:"forward local ports to the VM" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

open Lwt.Infix
open Vmnet

let is_windows = Sys.os_type = "Win32"

let failf fmt = Fmt.kstrf (fun e -> Lwt_result.fail (`Msg e)) fmt

module Make(Socket: Sig.SOCKETS) = struct

  module Channel = Mirage_channel_lwt.Make(Socket.Stream.Unix)

  let err_eof = Lwt_result.fail (`Msg "EOF")
  let err_read e = failf "while reading: %a" Channel.pp_error e
  let err_flush e = failf "while flushing: %a" Channel.pp_write_error e

  let with_read x f =
    x >>= function
    | Error e      -> err_read e
    | Ok `Eof      -> err_eof
    | Ok (`Data x) -> f x

  let with_flush x f =
    x >>= function
    | Error e -> err_flush e
    | Ok ()   -> f ()

  type t = {
    fd: Socket.Stream.Unix.flow;
    c: Channel.t;
  }

  let of_fd fd =
    let buf = Cstruct.create Init.sizeof in
    let (_: Cstruct.t) = Init.marshal Init.default buf in
    let c = Channel.create fd in
    Channel.write_buffer c buf;
    with_flush (Channel.flush c) @@ fun () ->
    with_read (Channel.read_exactly ~len:Init.sizeof c) @@ fun bufs ->
    let buf = Cstruct.concat bufs in
    let init, _ = Init.unmarshal buf in
    Log.info (fun f ->
        f "Client.negotiate: received %s" (Init.to_string init));
    Lwt_result.return { fd; c }

  let bind_ipv4 t (ipv4, port, stream) =
    let buf = Cstruct.create Command.sizeof in
    let (_: Cstruct.t) =
      Command.marshal (Command.Bind_ipv4(ipv4, port, stream)) buf
    in
    Channel.write_buffer t.c buf;
    with_flush (Channel.flush t.c) @@ fun () ->
    let rawfd = Socket.Stream.Unix.unsafe_get_raw_fd t.fd in
    let result = Bytes.make 8 '\000' in
    let n, _, fd = Fd_send_recv.recv_fd rawfd result 0 8 [] in

    (if n <> 8 then failf "Message only contained %d bytes" n else
       let buf = Cstruct.create 8 in
       Cstruct.blit_from_bytes result 0 buf 0 8;
       Log.debug (fun f ->
           let b = Buffer.create 16 in
           Cstruct.hexdump_to_buffer b buf;
           f "received result bytes: %s which is %s" (String.escaped (Bytes.to_string result))
             (Buffer.contents b));
       match Cstruct.LE.get_uint64 buf 0 with
       | 0L  -> Lwt_result.return fd
       | 48L -> failf "EADDRINUSE"
       | 49L -> failf "EADDRNOTAVAIL"
       | n   -> failf "Failed to bind: unrecognised errno: %Ld" n
    ) >>= function
    | Error x ->
      Unix.close fd;
      Lwt_result.fail x
    | Ok x ->
      Lwt_result.return x

  (* This implementation is OSX-only *)
  let request_privileged_port local_ip local_port sock_stream =
    let open Lwt_result.Infix in
    Socket.Stream.Unix.connect "/var/run/com.docker.vmnetd.sock"
    >>= fun flow ->
    Lwt.finalize (fun () ->
        of_fd flow >>= fun c ->
        bind_ipv4 c (local_ip, local_port, sock_stream)
      ) (fun () -> Socket.Stream.Unix.close flow)

  module Datagram = struct
    type address = Socket.Datagram.address

    module Udp = struct
      include Socket.Datagram.Udp

      let bind ?description (local_ip, local_port) =
        match local_ip with
        | Ipaddr.V4 ipv4 ->
          if local_port < 1024 && not is_windows then
            request_privileged_port ipv4 local_port false >>= function
            | Error (`Msg x) -> Lwt.fail_with x
            | Ok fd          -> Socket.Datagram.Udp.of_bound_fd fd
          else
            bind ?description (local_ip, local_port)
        | _ -> bind ?description (local_ip, local_port)
    end
  end

  module Stream = struct
    module Tcp = struct
      include Socket.Stream.Tcp

      let bind ?description (local_ip, local_port) =
        match local_ip with
        | Ipaddr.V4 ipv4 ->
          if local_port < 1024 && not is_windows then
            request_privileged_port ipv4 local_port true >>= function
            | Error (`Msg x) -> Lwt.fail_with x
            | Ok fd          -> Socket.Stream.Tcp.of_bound_fd fd
          else
            bind ?description (local_ip, local_port)
        | _ -> bind ?description (local_ip, local_port)
    end

    module Unix = Socket.Stream.Unix
  end
end

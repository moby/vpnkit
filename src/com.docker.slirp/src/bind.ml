let src =
  let src = Logs.Src.create "port forward" ~doc:"forward local ports to the VM" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

open Lwt.Infix

(* This implementation is OSX-only *)
let request_privileged_port local_ip local_port sock_stream =
  let s = Lwt_unix.socket Lwt_unix.PF_UNIX Lwt_unix.SOCK_STREAM 0 in
  Lwt.finalize
    (fun () ->
      Lwt_unix.connect s (Unix.ADDR_UNIX "/var/tmp/com.docker.vmnetd.socket")
      >>= fun () ->
      Vmnet_client.of_fd s
      >>= fun r ->
      begin match r with
      | `Error (`Msg x) -> Lwt.fail (Failure x)
      | `Ok c ->
        Vmnet_client.bind_ipv4 c (local_ip, local_port, sock_stream)
        >>= fun r ->
        begin match r with
        | `Ok fd ->
          Log.debug (fun f -> f "Received fd successfully");
          Lwt.return fd
        | `Error (`Msg x) ->
          Log.err (fun f -> f "Error binding to %s:%d: %s" (Ipaddr.V4.to_string local_ip) local_port x);
          Lwt.fail (Failure x)
        end
      end
    ) (fun () -> Lwt_unix.close s)

module Datagram = struct
  type address = Hostnet.Socket.Datagram.address
  type reply = Hostnet.Socket.Datagram.reply

  let input = Hostnet.Socket.Datagram.input

  module Udp = struct
    include Hostnet.Socket.Datagram.Udp

    let bind (local_ip, local_port) = match local_ip with
      | Ipaddr.V4 ipv4 ->
        if local_port < 1024 then begin
          request_privileged_port ipv4 local_port false
          >>= fun fd ->
          Lwt.return (Hostnet.Socket.Datagram.Udp.of_bound_fd fd)
        end else bind (local_ip, local_port)
      | _ -> bind (local_ip, local_port)
  end
end

module Stream = struct
  module Tcp = struct
    include Hostnet.Socket.Stream.Tcp

    let bind (local_ip, local_port) =
      if local_port < 1024 then begin
        request_privileged_port local_ip local_port true
        >>= fun fd ->
        Lwt.return (Hostnet.Socket.Stream.Tcp.of_bound_fd fd)
      end else bind (local_ip, local_port)
  end

  module Unix = Hostnet.Socket.Stream.Unix
end

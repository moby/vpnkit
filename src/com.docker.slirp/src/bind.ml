(*
 * Copyright (C) 2016 David Scott <dave.scott@docker.com>
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

let src =
  let src = Logs.Src.create "port forward" ~doc:"forward local ports to the VM" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

(* This implementation is OSX-only *)
let request_privileged_port local_ip local_port sock_stream =
  let s = Lwt_unix.socket Lwt_unix.PF_UNIX Lwt_unix.SOCK_STREAM 0 in
  Lwt.finalize
    (fun () ->
      let open Lwt.Infix in
      Lwt_unix.connect s (Unix.ADDR_UNIX "/var/tmp/com.docker.vmnetd.socket")
      >>= fun () ->
      Vmnet_client.of_fd s
      >>= fun r ->
      begin match r with
      | `Error (`Msg x) -> Lwt.return (Result.Error (`Msg x))
      | `Ok c ->
        Vmnet_client.bind_ipv4 c (local_ip, local_port, sock_stream)
        >>= fun r ->
        begin match r with
        | `Ok fd ->
          Log.debug (fun f -> f "Received fd successfully");
          Lwt.return (Result.Ok fd)
        | `Error (`Msg x) ->
          Log.err (fun f -> f "Error binding to %s:%d: %s" (Ipaddr.V4.to_string local_ip) local_port x);
          Lwt.return (Result.Error (`Msg x))
        end
      end
    ) (fun () -> Lwt_unix.close s)

let bind local_ip local_port stream =
  if local_port < 1024
  then request_privileged_port local_ip local_port stream
  else Hostnet.Port.bind local_ip local_port stream

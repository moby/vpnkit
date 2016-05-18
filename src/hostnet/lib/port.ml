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


let bind local_ip local_port sock_stream =
  let open Lwt.Infix in
    let addr = Lwt_unix.ADDR_INET(Unix.inet_addr_of_string (Ipaddr.V4.to_string local_ip), local_port) in
    let fd = Lwt_unix.socket Lwt_unix.PF_INET (if sock_stream then Lwt_unix.SOCK_STREAM else Lwt_unix.SOCK_DGRAM) 0 in
    Lwt.catch
      (fun () ->
       Lwt_unix.setsockopt fd Lwt_unix.SO_REUSEADDR true;
       Lwt_unix.bind fd addr;
       Lwt.return (Result.Ok fd))
      (fun e ->
       Lwt_unix.close fd
       >>= fun () ->
       Lwt.return (Result.Error (`Msg (Printf.sprintf "Failed to bind %s %s:%d %s"
         (if sock_stream then "SOCK_STREAM" else "SOCK_DGRAM")
         (Ipaddr.V4.to_string local_ip) local_port (Printexc.to_string e))))
      )

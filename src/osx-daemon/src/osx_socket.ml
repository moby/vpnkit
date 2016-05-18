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
open Lwt.Infix

let listen path =
  let startswith prefix x =
    let prefix' = String.length prefix in
    let x' = String.length x in
    prefix' <= x' && (String.sub x 0 prefix' = prefix) in
  if startswith "fd:" path then begin
    let i = String.sub path 3 (String.length path - 3) in
    let x = try int_of_string i with _ -> failwith (Printf.sprintf "Failed to parse command-line argument [%s]" path) in
    let fd = Unix_representations.file_descr_of_int x in
    Lwt.return (Lwt_unix.of_unix_file_descr fd)
  end else begin
    Lwt.catch
      (fun () -> Lwt_unix.unlink path)
      (function
        | Unix.Unix_error(Unix.ENOENT, _, _) -> Lwt.return ()
        | e -> Lwt.fail e)
    >>= fun () ->
    let s = Lwt_unix.socket Lwt_unix.PF_UNIX Lwt_unix.SOCK_STREAM 0 in
    Lwt_unix.bind s (Lwt_unix.ADDR_UNIX path);
    Lwt_unix.listen s 5;
    Lwt.return s
  end

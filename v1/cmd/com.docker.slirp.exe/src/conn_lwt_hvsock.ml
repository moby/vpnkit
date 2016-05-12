(*
 * Copyright (C) 2015 David Scott <dave.scott@unikernel.com>
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

type fd = Lwt_hvsock.t
let connect fd = fd
let close = Lwt_hvsock.close

let read fd buf =
  let len = Cstruct.len buf in
  let bytes = Bytes.make len '\000' in
  let rec loop ofs =
    if ofs >= len then Lwt.return ()
    else
      Lwt_hvsock.read fd bytes ofs (len - ofs)
      >>= fun n ->
      loop (ofs + n) in
  loop 0
  >>= fun () ->
  Cstruct.blit_from_string bytes 0 buf 0 len;
  Lwt.return ()

let write fd buf =
  let len = Cstruct.len buf in
  let bytes = Cstruct.to_string buf in
  let rec loop ofs =
    if ofs >= len then Lwt.return ()
    else
      Lwt_hvsock.write fd bytes ofs (len - ofs)
      >>= fun n ->
      loop (ofs + n) in
  loop 0

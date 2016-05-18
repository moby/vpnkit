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

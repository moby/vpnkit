open Lwt.Infix

type fd = Lwt_unix.file_descr
let connect fd = fd
let close = Lwt_unix.close

let read fd buf = Lwt_cstruct.(complete (read fd) buf)
let write fd buf = Lwt_cstruct.(complete (write fd) buf)

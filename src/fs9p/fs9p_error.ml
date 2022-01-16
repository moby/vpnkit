(* Must match exactly what Linux is expecting *)

open Rresult

type t = Protocol_9p.Response.Err.t

let error ?(errno = 0l) fmt =
  Printf.ksprintf
    (fun ename -> Error { Protocol_9p.Response.Err.ename; errno = Some errno })
    fmt

let enoent = error "No such file or directory"

let eisdir = error "Is a directory"

let enotdir = error "Is not a directory"

let ero = error "Read-only file"

let eperm = error "Operation not permitted"

let of_error x =
  let open Vfs.Error in
  match x with
  | Noent -> enoent
  | Isdir -> eisdir
  | Notdir -> enotdir
  | Read_only_file -> ero
  | Perm -> eperm
  | Other err -> error ?errno:err.errno "%s" err.descr

let map_error = function
  | Ok _ as x -> Lwt.return x
  | Error e -> Lwt.return (of_error e)

module Infix = struct
  open Lwt.Infix

  let ( >>*= ) x f =
    x >>= function Ok x -> f x | Error _ as e -> Lwt.return e
end

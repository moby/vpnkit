open Lwt

let src =
  let src = Logs.Src.create "usernet" ~doc:"Mirage TCP/IP <-> socket proxy" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

type 'a io = 'a Lwt.t

type buffer = Cstruct.t

type error = Unix.error

let error_message = Unix.error_message

type flow = {
  fd: Lwt_unix.file_descr;
  read_buffer_size: int;
  mutable closed: bool;
}

let connect fd =
  let read_buffer_size = 1024 in
  let closed = false in
  { fd; read_buffer_size; closed }

let close t =
  match t.closed with
  | false ->
    t.closed <- true;
    Lwt_unix.close t.fd
  | true ->
    Lwt.return ()

let read flow =
  if flow.closed then return `Eof
  else
    let buffer = Lwt_bytes.create flow.read_buffer_size in
    Lwt_bytes.read flow.fd buffer 0 (Lwt_bytes.length buffer)
    >>= function
    | 0 ->
      return `Eof
    | n ->
      return (`Ok (Cstruct.(sub (of_bigarray buffer) 0 n)))

let read_into flow buffer =
  if flow.closed then return `Eof
  else
    Lwt.catch
      (fun () ->
        Lwt_cstruct.(complete (read flow.fd) buffer)
        >>= fun () ->
        return (`Ok ())
      ) (fun _e -> return `Eof)

let write flow buf =
  if flow.closed then return `Eof
  else
    Lwt.catch
      (fun () ->
        Lwt_cstruct.(complete (write flow.fd) buf)
        >>= fun () ->
        return (`Ok ())
      ) (function
        | Unix.Unix_error(Unix.EPIPE, _, _) -> return `Eof
        | e -> fail e)

let writev flow bufs =
  let rec loop = function
    | [] -> return (`Ok ())
    | x :: xs ->
      if flow.closed then return `Eof
      else
        Lwt.catch
          (fun () ->
            Lwt_cstruct.(complete (write flow.fd) x)
            >>= fun () ->
            loop xs
          ) (function
            | Unix.Unix_error(Unix.EPIPE, _, _) -> return `Eof
            | e -> fail e) in
  loop bufs

let shutdown_write flow =
  try
    Lwt_unix.shutdown flow.fd Unix.SHUTDOWN_SEND;
    Lwt.return ()
  with
  | Unix.Unix_error(Unix.ENOTCONN, _, _) -> Lwt.return ()
  | e ->
    Log.err (fun f -> f "Socket_stack.TCPV4.shutdown_write: caught %s returning Eof" (Printexc.to_string e));
    Lwt.return ()

let shutdown_read flow =
  try
    Lwt_unix.shutdown flow.fd Unix.SHUTDOWN_RECEIVE;
    Lwt.return ()
  with
  | Unix.Unix_error(Unix.ENOTCONN, _, _) -> Lwt.return ()
  | e ->
    Log.err (fun f -> f "Socket_stack.TCPV4.shutdown_read: caught %s returning Eof" (Printexc.to_string e));
    Lwt.return ()

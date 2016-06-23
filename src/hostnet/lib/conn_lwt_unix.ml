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
  mutable read_buffer: Cstruct.t; (* contains free space available for reading *)
  mutable closed: bool;
}

let connect fd =
  let read_buffer_size = 65536 in
  let read_buffer = Cstruct.create read_buffer_size in
  let closed = false in
  { fd; read_buffer_size; read_buffer; closed }

let close t =
  match t.closed with
  | false ->
    t.closed <- true;
    Lwt_unix.close t.fd
  | true ->
    Lwt.return ()

let read flow =
  if flow.closed then return `Eof
  else begin
    if Cstruct.len flow.read_buffer = 0
    then flow.read_buffer <- Cstruct.create flow.read_buffer_size;
    let open Cstruct in
    Lwt_bytes.read flow.fd flow.read_buffer.buffer flow.read_buffer.off flow.read_buffer.len
    >>= function
    | 0 ->
      return `Eof
    | n ->
      let result = Cstruct.sub flow.read_buffer 0 n in
      flow.read_buffer <- Cstruct.shift flow.read_buffer n;
      return (`Ok result)
  end

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

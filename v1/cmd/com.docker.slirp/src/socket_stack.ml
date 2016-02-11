
let src =
  let src = Logs.Src.create "usernet" ~doc:"Mirage TCP/IP <-> socket proxy" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

include Tcpip_stack_socket.Make(Console_unix)

module TCPV4_half_close = struct
  include TCPV4

  let shutdown_write fd =
    try
      Lwt_unix.shutdown fd Unix.SHUTDOWN_RECEIVE;
      Lwt.return ()
    with
    | Unix.Unix_error(Unix.ENOTCONN, _, _) -> Lwt.return ()
    | e ->
      Log.err (fun f -> f "Socket_stack.TCPV4.shutdown_read: caught %s returning Eof" (Printexc.to_string e));
      Lwt.return ()

  let shutdown_read fd =
    try
      Lwt_unix.shutdown fd Unix.SHUTDOWN_SEND;
      Lwt.return ()
    with
    | Unix.Unix_error(Unix.ENOTCONN, _, _) -> Lwt.return ()
    | e ->
      Log.err (fun f -> f "Socket_stack.TCPV4.shutdown_send: caught %s returning Eof" (Printexc.to_string e));
      Lwt.return ()
end


let src =
  let src = Logs.Src.create "usernet" ~doc:"Mirage TCP/IP <-> socket proxy" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

include Tcpip_stack_socket.Make(Console_unix)

module Infix = struct
  open Lwt.Infix
  let ( >>= ) m f = m >>= function
    | `Ok x -> f x
    | `Error x -> Lwt.return (`Error x)
end

let or_error name m =
  let open Lwt.Infix in
  m >>= function
  | `Error _ -> Lwt.return (`Error (`Msg (Printf.sprintf "Failed to connect %s device" name)))
  | `Ok x -> Lwt.return (`Ok x)

let connect () =
  let open Infix in
  or_error "console" @@ Console_unix.connect "0"
  >>= fun console ->
  or_error "udpv4" @@ Udpv4_socket.connect None
  >>= fun udpv4 ->
  or_error "tcpv4" @@ Tcpv4_socket.connect None
  >>= fun tcpv4 ->
  (* let netmask = Ipaddr.V4.Prefix.netmask config.prefix in *)
  let cfg = {
    V1_LWT. name = "socketv4_ip";
    console;
    mode = ();
    interface = [ Ipaddr.V4.any ];
    (* mode = `IPv4 (config.local_ip, netmask, []); *)
  } in
  or_error "stack" @@ connect cfg udpv4 tcpv4

module TCPV4_half_close = struct
  include TCPV4

  let shutdown_write fd =
    try
      Lwt_unix.shutdown fd Unix.SHUTDOWN_SEND;
      Lwt.return ()
    with
    | Unix.Unix_error(Unix.ENOTCONN, _, _) -> Lwt.return ()
    | e ->
      Log.err (fun f -> f "Socket_stack.TCPV4.shutdown_write: caught %s returning Eof" (Printexc.to_string e));
      Lwt.return ()

  let shutdown_read fd =
    try
      Lwt_unix.shutdown fd Unix.SHUTDOWN_RECEIVE;
      Lwt.return ()
    with
    | Unix.Unix_error(Unix.ENOTCONN, _, _) -> Lwt.return ()
    | e ->
      Log.err (fun f -> f "Socket_stack.TCPV4.shutdown_read: caught %s returning Eof" (Printexc.to_string e));
      Lwt.return ()
end

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

let src =
  let src = Logs.Src.create "usernet" ~doc:"Unix socket connections" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module UDPV4 = struct
  type reply = Cstruct.t -> unit Lwt.t

  type flow = {
    fd: Lwt_unix.file_descr;
    ip: Ipaddr.V4.t;
    port: int;
    mutable last_use: float;
    (* For protocols like NTP the source port keeps changing, so we send
       replies to the last source port we saw. *)
    mutable reply: reply;
  }

  (* If we spot one older than this then we'll delete it *)
  let max_age = 60.

  (* Look up by dst * dst_port *)
  let table = Hashtbl.create 7

  let _ =
    let rec loop () =
      let open Lwt.Infix in
      Lwt_unix.sleep 60.
      >>= fun () ->
      let snapshot = Hashtbl.copy table in
      let now = Unix.gettimeofday () in
      Hashtbl.iter (fun k flow ->
          if now -. flow.last_use > 60. then begin
            Log.info (fun f -> f "expiring UDP NAT rule for %s:%d" (Ipaddr.V4.to_string flow.ip) flow.port);
            Lwt.async (fun () -> Lwt_unix.close flow.fd);
            Hashtbl.remove table k
          end
        ) snapshot;
      loop () in
    loop ()

  let input ~reply ~src:(src, src_port) ~dst:(dst, dst_port) ~payload =
    let open Lwt.Infix in
    let remote_sockaddr = Unix.ADDR_INET(Unix.inet_addr_of_string @@ Ipaddr.V4.to_string dst, dst_port) in
    (if Hashtbl.mem table (dst, dst_port) then begin
        Lwt.return (Hashtbl.find table (dst, dst_port))
      end else begin
       Log.info (fun f -> f "connecting UDP socket to %s:%d" (Ipaddr.V4.to_string dst) dst_port);
       let fd = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_DGRAM 0 in
       let last_use = Unix.gettimeofday () in
       let ip = dst and port = dst_port in
       let flow = { fd; last_use; reply; ip; port } in
       Hashtbl.replace table (dst, dst_port) flow;
       (* Start a listener *)
       let buffer = Cstruct.create 1500 in
       let rec loop () =
         Lwt.catch
           (fun () ->
              Lwt_bytes.recvfrom fd buffer.Cstruct.buffer buffer.Cstruct.off buffer.Cstruct.len []
              >>= fun (n, _) ->
              let response = Cstruct.sub buffer 0 n in
              flow.reply response
              >>= fun () ->
              Lwt.return true
           ) (fun e ->
               Log.err (fun f -> f "Usernet_lwt_unix.UDPV4 recv caught %s" (Printexc.to_string e));
               Lwt.return false
             )
         >>= function
         | false -> Lwt.return ()
         | true -> loop () in
       Lwt.async loop;
       Lwt.return flow
     end) >>= fun flow ->
    flow.reply <- reply;
    Lwt.catch
      (fun () ->
         Lwt_bytes.sendto flow.fd payload.Cstruct.buffer payload.Cstruct.off payload.Cstruct.len [] remote_sockaddr
         >>= fun n ->
         if n <> payload.Cstruct.len
         then Log.err (fun f -> f "Lwt_bytes.send short: expected %d got %d" payload.Cstruct.len n);
         flow.last_use <- Unix.gettimeofday ();
         Lwt.return ()
      ) (fun e ->
          Log.err (fun f -> f "Lwt_bytes.send to %s:%d caught %s" (Ipaddr.V4.to_string dst) dst_port (Printexc.to_string e));
          Lwt.return ()
        )

end

module TCPV4 = struct

  type flow = {
    fd: Lwt_unix.file_descr;
    read_buffer_size: int;
    mutable read_buffer: Cstruct.t;
    mutable closed: bool;
  }

  type error = [
    | `Msg of string
  ]

  let error_message = function
    | `Msg x -> x

  let errorf fmt = Printf.ksprintf (fun s -> Lwt.return (`Error (`Msg s))) fmt

  let connect_v4 ?(read_buffer_size = 65536) ip port =
    let open Lwt.Infix in
    let fd = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_STREAM 0 in
    Lwt.catch
      (fun () ->
         Log.info (fun f -> f "connecting to %s port %d" (Ipaddr.V4.to_string ip) port);
         Lwt_unix.connect fd (Unix.ADDR_INET (Unix.inet_addr_of_string @@ Ipaddr.V4.to_string ip, port))
         >>= fun () ->
         let read_buffer = Cstruct.create read_buffer_size in
         let closed = false in
         Lwt.return (`Ok { fd; read_buffer; read_buffer_size; closed })
      )
      (fun e ->
         Lwt_unix.close fd
         >>= fun () ->
         errorf "Lwt_unix.connect %s: %s" (Ipaddr.V4.to_string ip) (Printexc.to_string e)
      )

  let shutdown_read { fd; closed } =
    try
      if not closed then Lwt_unix.shutdown fd Unix.SHUTDOWN_RECEIVE;
      Lwt.return ()
    with
    | Unix.Unix_error(Unix.ENOTCONN, _, _) -> Lwt.return ()
    | e ->
      Log.err (fun f -> f "shutdown_read caught %s" (Printexc.to_string e));
      Lwt.return ()

  let shutdown_write { fd; closed } =
    try
      if not closed then Lwt_unix.shutdown fd Unix.SHUTDOWN_SEND;
      Lwt.return ()
    with
    | Unix.Unix_error(Unix.ENOTCONN, _, _) -> Lwt.return ()
    | e ->
      Log.err (fun f -> f "shutdown_write caught %s" (Printexc.to_string e));
      Lwt.return ()

  let read t =
    let open Lwt.Infix in
    (if Cstruct.len t.read_buffer = 0 then t.read_buffer <- Cstruct.create t.read_buffer_size);
    Lwt.catch
      (fun () ->
         Lwt_bytes.read t.fd t.read_buffer.Cstruct.buffer t.read_buffer.Cstruct.off t.read_buffer.Cstruct.len
         >>= function
         | 0 -> Lwt.return `Eof
         | n ->
           let results = Cstruct.sub t.read_buffer 0 n in
           t.read_buffer <- Cstruct.shift t.read_buffer n;
           Lwt.return (`Ok results)
      ) (fun e ->
          Log.err (fun f -> f "Socket.TCPV4.read caught %s" (Printexc.to_string e));
          Lwt.return `Eof
        )

  let write t buf =
    let open Lwt.Infix in
    Lwt.catch
      (fun () ->
         Lwt_cstruct.(complete (write t.fd) buf)
         >>= fun () ->
         Lwt.return (`Ok ())
      ) (fun e ->
          Log.err (fun f -> f "Socket.TCP4.write caught %s" (Printexc.to_string e));
          Lwt.return `Eof
        )

  let writev t bufs =
    Lwt.catch
      (fun () ->
         let open Lwt.Infix in
         let rec loop = function
           | [] -> Lwt.return (`Ok ())
           | buf :: bufs ->
             Lwt_cstruct.(complete (write t.fd) buf)
             >>= fun () ->
             loop bufs in
         loop bufs
      ) (fun e ->
          Log.err (fun f -> f "Socket.TCP4.writev caught %s" (Printexc.to_string e));
          Lwt.return `Eof
        )

  let close t =
    if not t.closed then (t.closed <- true; Lwt_unix.close t.fd) else Lwt.return ()


  (* FLOW boilerplate *)
  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t

end

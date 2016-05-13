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
  let src = Logs.Src.create "socket" ~doc:"Unix socket connections" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let broadcast = Ipaddr.V4.of_string_exn "255.255.255.255"

module Datagram = struct
  type reply = Cstruct.t -> unit Lwt.t

  type flow = {
    description: string;
    fd: Lwt_unix.file_descr;
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
            Log.debug (fun f -> f "Socket.Datagram %s: expiring UDP NAT rule" flow.description);
            Lwt.async (fun () ->
              Lwt.catch (fun () ->
                Lwt_unix.close flow.fd
              ) (fun e ->
                Log.err (fun f -> f "Socket.Datagram %s: caught %s while closing UDP socket" flow.description (Printexc.to_string e));
                Lwt.return ()
              )
            );
            Hashtbl.remove table k
          end
        ) snapshot;
      loop () in
    loop ()

  let input ~reply ~src:(src, src_port) ~dst:(dst, dst_port) ~payload =
    let open Lwt.Infix in
    let remote_sockaddr = Unix.ADDR_INET(Unix.inet_addr_of_string @@ Ipaddr.V4.to_string dst, dst_port) in
    (if Hashtbl.mem table (dst, dst_port) then begin
        Lwt.return (Some (Hashtbl.find table (dst, dst_port)))
      end else begin
       let description = Ipaddr.V4.to_string dst ^ ":" ^ (string_of_int dst_port) in
       if Ipaddr.V4.compare dst broadcast = 0 then begin
         Log.debug (fun f -> f "Socket.Datagram.input %s: ignoring broadcast packet" description);
         Lwt.return None
       end else begin
         Log.debug (fun f -> f "Socket.Datagram.input %s: creating UDP NAT rule" description);
         let fd = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_DGRAM 0 in
         Lwt_unix.bind fd (Lwt_unix.ADDR_INET(Unix.inet_addr_any, 0));
         let last_use = Unix.gettimeofday () in
         let flow = { description; fd; last_use; reply} in
         Hashtbl.replace table (dst, dst_port) flow;
         (* Start a listener *)
         let buffer = Cstruct.create 1500 in
         let bytes = Bytes.make 1500 '\000' in
         let rec loop () =
           Lwt.catch
             (fun () ->
                (* Lwt on Win32 doesn't support Lwt_bytes.recvfrom *)
                Lwt_unix.recvfrom fd bytes 0 (String.length bytes) []
                >>= fun (n, _) ->
                Cstruct.blit_from_string bytes 0 buffer 0 n;
                let response = Cstruct.sub buffer 0 n in
                flow.reply response
                >>= fun () ->
                Lwt.return true
             ) (function
                 | Unix.Unix_error(Unix.EBADF, _, _) ->
                   (* fd has been closed by the GC *)
                   Log.debug (fun f -> f "Socket.Datagram.input %s: shutting down listening thread" description);
                   Lwt.return false
                 | e ->
                   Log.err (fun f -> f "Socket.Datagram.input %s: caught unexpected exception %s" description (Printexc.to_string e));
                   Lwt.return false
               )
           >>= function
           | false -> Lwt.return ()
           | true -> loop () in
         Lwt.async loop;
         Lwt.return (Some flow)
       end
     end) >>= function
    | None -> Lwt.return ()
    | Some flow ->
      flow.reply <- reply;
      Lwt.catch
        (fun () ->
           (* Lwt on Win32 doesn't support Lwt_bytes.sendto *)
           let payload_string = Cstruct.to_string payload in
           Lwt_unix.sendto flow.fd payload_string 0 (String.length payload_string) [] remote_sockaddr
           >>= fun n ->
           if n <> payload.Cstruct.len
           then Log.err (fun f -> f "Socket.Datagram.input %s: Lwt_bytes.send short: expected %d got %d" flow.description payload.Cstruct.len n);
           flow.last_use <- Unix.gettimeofday ();
           Lwt.return ()
        ) (fun e ->
            Log.err (fun f -> f "Socket.Datagram.input %s: Lwt_bytes.send caught %s" flow.description (Printexc.to_string e));
            Lwt.return ()
          )

end

module Stream = struct

  type flow = {
    description: string;
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

  let of_fd ?(read_buffer_size = 65536) ~description fd =
    let read_buffer = Cstruct.create read_buffer_size in
    let closed = false in
    { description; fd; read_buffer; read_buffer_size; closed }

  let connect_v4 ?(read_buffer_size = 65536) ip port =
    let open Lwt.Infix in
    let fd = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_STREAM 0 in
    let description = Ipaddr.V4.to_string ip ^ ":" ^ (string_of_int port) in
    Lwt.catch
      (fun () ->
         Log.debug (fun f -> f "Socket.TCPV4.connect_v4 %s: connecting" description);
         Lwt_unix.connect fd (Unix.ADDR_INET (Unix.inet_addr_of_string @@ Ipaddr.V4.to_string ip, port))
         >>= fun () ->
         Lwt.return (`Ok (of_fd ~read_buffer_size ~description fd))
      )
      (fun e ->
         Lwt_unix.close fd
         >>= fun () ->
         errorf "Socket.TCPV4.connect_v4 %s: Lwt_unix.connect: caught %s" description (Printexc.to_string e)
      )

  let shutdown_read { description; fd; closed } =
    try
      if not closed then Lwt_unix.shutdown fd Unix.SHUTDOWN_RECEIVE;
      Lwt.return ()
    with
    | Unix.Unix_error(Unix.ENOTCONN, _, _) -> Lwt.return ()
    | e ->
      Log.err (fun f -> f "Socket.TCPV4.shutdown_read %s: caught %s returning Eof" description (Printexc.to_string e));
      Lwt.return ()

  let shutdown_write { description; fd; closed } =
    try
      if not closed then Lwt_unix.shutdown fd Unix.SHUTDOWN_SEND;
      Lwt.return ()
    with
    | Unix.Unix_error(Unix.ENOTCONN, _, _) -> Lwt.return ()
    | e ->
      Log.err (fun f -> f "Socket.TCPV4.shutdown_write %s: caught %s returning Eof" description (Printexc.to_string e));
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
          Log.err (fun f -> f "Socket.TCPV4.read %s: caught %s returning Eof" t.description (Printexc.to_string e));
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
          Log.err (fun f -> f "Socket.TCPV4.write %s: caught %s returning Eof" t.description (Printexc.to_string e));
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
          Log.err (fun f -> f "Socket.TCPV4.writev %s: caught %s returning Eof" t.description (Printexc.to_string e));
          Lwt.return `Eof
        )

  let close t =
    if not t.closed then begin
      t.closed <- true;
      Lwt_unix.close t.fd
    end else Lwt.return ()

  (* FLOW boilerplate *)
  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t

end

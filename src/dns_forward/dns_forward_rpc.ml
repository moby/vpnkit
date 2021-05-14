(*
 * Copyright (C) 2016 David Scott <dave@recoil.org>
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
  let src = Logs.Src.create "Dns_forward" ~doc:"DNS over SOCKETS" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Client = struct

  module type S = Dns_forward_s.RPC_CLIENT

  module Nonpersistent = struct
    module Make
      (Sockets: Dns_forward_s.FLOW_CLIENT with type address = Ipaddr.t * int)
      (Packet: Dns_forward_s.READERWRITER with type flow = Sockets.flow)
      (Time: Mirage_time.S) = struct
        type address = Dns_forward_config.Address.t
        type request = Cstruct.t
        type response = Cstruct.t

        type message_cb = ?src:address -> ?dst:address -> buf:Cstruct.t -> unit -> unit Lwt.t

        type t = {
          address: address;
          free_ids: Dns_forward_free_id.t;
          message_cb: message_cb;
        }

        let connect
          ~gen_transaction_id
          ?(message_cb = fun ?src:_ ?dst:_ ~buf:_ () -> Lwt.return_unit)
          address =
          let free_ids = Dns_forward_free_id.make ~g:gen_transaction_id () in
          Lwt_result.return { address; free_ids; message_cb }

        let to_string t = Dns_forward_config.Address.to_string t.address

        let rpc (t: t) buffer =
          let buf = buffer in
          match Dns.Protocol.Server.parse (Cstruct.sub buf 0 (Cstruct.len buffer)) with
          | Some request ->
            (* Although we aren't multiplexing requests on the same flow (unlike the
               Persistent case below) we still rewrite the request id
               - to limit the number of sockets we allocate
               - to work around clients who use predictable request ids *)

              (* The id whose scope is the link to the client *)
              let client_id = request.Dns.Packet.id in
              (* The id whose scope is the link to the server *)
              Dns_forward_free_id.with_id t.free_ids
                (fun free_id ->
                  (* Copy the buffer since this function will be run in parallel with the
                     same buffer *)
                  let buffer =
                    let tmp = Cstruct.create (Cstruct.len buffer) in
                    Cstruct.blit buffer 0 tmp 0 (Cstruct.len buffer);
                    tmp in
                  (* Rewrite the query id before forwarding *)
                  Cstruct.BE.set_uint16 buffer 0 free_id;
                  Log.debug (fun f -> f "%s mapping DNS id %d -> %d" (to_string t) client_id free_id);

                  let open Lwt_result.Infix in
                  Sockets.connect (t.address.Dns_forward_config.Address.ip, t.address.Dns_forward_config.Address.port)
                  >>= fun flow ->
                  Lwt.finalize
                    (fun () ->
                      let rw = Packet.connect flow in
                      let open Lwt.Infix in
                      t.message_cb ~dst:t.address ~buf:buffer ()
                      >>= fun () ->
                      let open Lwt_result.Infix in

                      (* An existing connection to the server might have been closed by the server;
                        therefore if we fail to write the request, reconnect and try once more. *)
                      Packet.write rw buffer
                      >>= fun () ->
                      Packet.read rw
                      >>= fun buf ->
                      let open Lwt.Infix in
                      t.message_cb ~src:t.address ~buf ()
                      >>= fun () ->
                      (* Rewrite the query id back to the original *)
                      Cstruct.BE.set_uint16 buf 0 client_id;
                      Lwt_result.return buf
                    ) (fun () ->
                      Sockets.close flow
                    )
                )
          | _ ->
          Log.err (fun f -> f "%s: rpc: failed to parse request" (to_string t));
          Lwt_result.fail (`Msg (to_string t ^ ":failed to parse request"))

        let disconnect _ =
          Lwt.return_unit
    end
  end

  module Persistent = struct
  module Make
      (Sockets: Dns_forward_s.FLOW_CLIENT with type address = Ipaddr.t * int)
      (Packet: Dns_forward_s.READERWRITER with type flow = Sockets.flow)
      (Time: Mirage_time.S) = struct
    type address = Dns_forward_config.Address.t
    type request = Cstruct.t
    type response = Cstruct.t

    type message_cb = ?src:address -> ?dst:address -> buf:Cstruct.t -> unit -> unit Lwt.t

    type t = {
      address: address;
      mutable client_address: address;
      mutable rw: Packet.t option;
      mutable disconnect_on_idle: unit Lwt.t;
      wakeners: (int, Dns.Packet.question * ((Cstruct.t, [ `Msg of string ]) result Lwt.u)) Hashtbl.t;
      m: Lwt_mutex.t;
      free_ids: Dns_forward_free_id.t;
      message_cb: message_cb;
    }

    module FlowError = Dns_forward_error.FromFlowError(Sockets)

    let to_string t = Dns_forward_config.Address.to_string t.client_address

    let disconnect t =
      Lwt_mutex.with_lock t.m
        (fun () ->
           match t with
           | { rw = Some rw; _ } as t ->
               t.rw <- None;
               let error = Error (`Msg (to_string t ^ ": connection to server was closed")) in
               Hashtbl.iter (fun id (question, u) ->
                   Log.info (fun f -> f "%s %04x: disconnect: failing request for question %s"
                                (to_string t) id
                                (Dns.Packet.question_to_string question)
                            );
                   (* It's possible that the response just arrived but hasn't been
                      processed by the client thread *)
                   try Lwt.wakeup_later u error
                   with Invalid_argument _ ->
                     Log.warn (fun f -> f "%s %04x: disconnect: response for DNS request just arrived in time" (to_string t) id)
                 ) t.wakeners;
               Packet.close rw
           | _ -> Lwt.return_unit
        )

    (* Receive all the responses and demux to the right thread. When the connection
       is closed, `read_buffer` will fail and this thread will exit. *)
    let dispatcher t rw () =
      let open Lwt.Infix in
      let rec loop () =
        Packet.read rw
        >>= function
        | Error (`Msg m) ->
            Log.debug (fun f -> f "%s: dispatcher shutting down: %s" (to_string t) m);
            disconnect t
        | Ok buffer ->
            let buf = buffer in
            begin match Dns.Protocol.Server.parse (Cstruct.sub buf 0 (Cstruct.len buffer)) with
            | Some ({ Dns.Packet.questions = [ question ]; _ } as response) ->
                let client_id = response.Dns.Packet.id in
                if Hashtbl.mem t.wakeners client_id then begin
                  let expected_question, u = Hashtbl.find t.wakeners client_id in
                  if expected_question <> question then begin
                    Log.warn (fun f -> f "%s %04x: response arrived for a different question: expected %s <> got %s"
                                 (to_string t) client_id
                                 (Dns.Packet.question_to_string expected_question)
                                 (Dns.Packet.question_to_string question)
                             )
                  end else begin
                    (* It's possible that disconnect has already failed the thread *)
                    try Lwt.wakeup_later u (Ok buffer)
                    with Invalid_argument _ ->
                      Log.warn (fun f -> f "%s %04x: response arrived for DNS request just after disconnection" (to_string t) client_id)
                  end
                end else begin
                  Log.debug (fun f -> f "%s %04x: no wakener: it was probably cancelled" (to_string t) client_id);
                end;
                loop ()
            | _ ->
                Log.err (fun f -> f "%s: dispatcher failed to parse response" (to_string t));
                Lwt.fail (Failure "failed to parse response")
            end
      in
      Lwt.catch loop
        (fun e ->
           Log.info (fun f -> f "%s dispatcher caught %s" (to_string t) (Printexc.to_string e));
           Lwt.return_unit
        )

    let get_rw t =
      let open Lwt_result.Infix in
      Lwt.cancel t.disconnect_on_idle;
      Lwt_mutex.with_lock t.m
        (fun () -> match t.rw with
          | None ->
              Sockets.connect (t.address.Dns_forward_config.Address.ip, t.address.Dns_forward_config.Address.port)
              >>= fun flow ->
              let rw = Packet.connect flow in
              t.rw <- Some rw;
              Lwt.async (dispatcher t rw);
              Lwt_result.return rw
          | Some rw ->
              Lwt_result.return rw)
      >>= fun rw ->
      (* Add a fresh idle timer *)
      t.disconnect_on_idle <- (let open Lwt.Infix in Time.sleep_ns Duration.(of_sec 30) >>= fun () -> disconnect t);
      Lwt_result.return rw

    let connect ~gen_transaction_id ?(message_cb = fun ?src:_ ?dst:_ ~buf:_ () -> Lwt.return_unit) address =
      let rw = None in
      let m = Lwt_mutex.create () in
      let disconnect_on_idle = Lwt.return_unit in
      let wakeners = Hashtbl.create 7 in
      let free_ids = Dns_forward_free_id.make ~g:gen_transaction_id () in
      let client_address = { Dns_forward_config.Address.ip = Ipaddr.V4 Ipaddr.V4.localhost; port = 0 } in
      Lwt_result.return { client_address; address; rw; disconnect_on_idle; wakeners; m; free_ids; message_cb }

    let rpc (t: t) buffer =
      let buf = buffer in
      match Dns.Protocol.Server.parse (Cstruct.sub buf 0 (Cstruct.len buffer)) with
      | Some ({ Dns.Packet.questions = [ question ]; _ } as request) ->
          (* Note: the received request id is scoped to the connection with the
             client. Since we are multiplexing requests to a single server we need
             to track used/unused ids on the link to the server and remember the
             mapping to the client. *)

          (* The id whose scope is the link to the client *)
          let client_id = request.Dns.Packet.id in
          (* The id whose scope is the link to the server *)
          Dns_forward_free_id.with_id t.free_ids
            (fun free_id ->
               Lwt.finalize
                 (fun () ->
                    (* Copy the buffer since this function will be run in parallel with the
                       same buffer *)
                    let buffer =
                      let tmp = Cstruct.create (Cstruct.len buffer) in
                      Cstruct.blit buffer 0 tmp 0 (Cstruct.len buffer);
                      tmp in
                    (* Rewrite the query id before forwarding *)
                    Cstruct.BE.set_uint16 buffer 0 free_id;
                    Log.debug (fun f -> f "%s mapping DNS id %d -> %d" (to_string t) client_id free_id);

                    let th, u = Lwt.task () in
                    Hashtbl.replace t.wakeners free_id (question, u);

                    (* If we fail to connect, return the error *)
                    let open Lwt.Infix in
                    begin
                      let open Lwt_result.Infix in
                      get_rw t
                      >>= fun rw ->
                      let open Lwt.Infix in
                      t.message_cb ~dst:t.address ~buf:buffer ()
                      >>= fun () ->
                      (* An existing connection to the server might have been closed by the server;
                         therefore if we fail to write the request, reconnect and try once more. *)
                      Packet.write rw buffer
                      >>= function
                      | Ok () ->
                          Lwt_result.return ()
                      | Error (`Msg m) ->
                          Log.info (fun f -> f "%s: caught %s writing request, attempting to reconnect" (to_string t) m);
                          disconnect t
                          >>= fun () ->
                          let open Lwt_result.Infix in
                          get_rw t
                          >>= fun rw ->
                          let open Lwt.Infix in
                          t.message_cb ~dst:t.address ~buf:buffer ()
                          >>= fun () ->
                          Packet.write rw buffer
                    end
                    >>= function
                    | Error (`Msg m) ->
                        Lwt_result.fail (`Msg m)
                    | Ok () ->
                        let open Lwt_result.Infix in
                        th (* will be woken up by the dispatcher *)
                        >>= fun buf ->
                        let open Lwt.Infix in
                        t.message_cb ~src:t.address ~buf ()
                        >>= fun () ->
                        (* Rewrite the query id back to the original *)
                        Cstruct.BE.set_uint16 buf 0 client_id;
                        Lwt_result.return buf
                 ) (fun () ->
                     (* This happens on cancel, disconnect, successful response *)
                     Hashtbl.remove t.wakeners free_id;
                     Lwt.return_unit
                   )
            )
      | _ ->
          Log.err (fun f -> f "%s: rpc: failed to parse request" (to_string t));
          Lwt_result.fail (`Msg (to_string t ^ ":failed to parse request"))
  end
end
end

module Server = struct

  module type S = Dns_forward_s.RPC_SERVER

  module Make
      (Sockets: Dns_forward_s.FLOW_SERVER with type address = Ipaddr.t * int)
      (Packet : Dns_forward_s.READERWRITER with type flow = Sockets.flow)
      (Time   : Mirage_time.S) =
  struct

    type address = Dns_forward_config.Address.t
    type request = Cstruct.t
    type response = Cstruct.t

    type server = {
      address: address;
      server: Sockets.server;
    }

    let bind address =
      let open Lwt_result.Infix in
      Sockets.bind (address.Dns_forward_config.Address.ip, address.Dns_forward_config.Address.port)
      >>= fun server ->
      Lwt_result.return { address; server }

    let listen { server; _ } cb =
      Sockets.listen server (fun flow ->
          let open Lwt.Infix in
          let rw = Packet.connect flow in
          let rec loop () =
            let open Lwt_result.Infix in
            Packet.read rw
            >>= fun request ->
            Lwt.async
              (fun () ->
                 let open Lwt.Infix in
                 cb request
                 >>= function
                 | Error _ ->
                     Lwt.return_unit
                 | Ok response ->
                     Packet.write rw response
                     >>= fun _ ->
                     Lwt.return_unit
              );
            loop () in
          loop ()
          >>= function
          | Error (`Msg m) ->
              Log.err (fun f -> f "server loop failed with: %s" m);
              Lwt.return_unit
          | Ok () ->
              Lwt.return_unit
        );
      Lwt_result.return ()

    let shutdown server =
      Sockets.shutdown server.server

  end
end

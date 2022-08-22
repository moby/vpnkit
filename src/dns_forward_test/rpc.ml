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
open Dns_forward
module Error = Error.Infix

let errorf fmt = Printf.ksprintf (fun s -> Lwt.return (Result.Error (`Msg s))) fmt

type request = Cstruct.t
type response = Cstruct.t
type address = Config.Address.t
let string_of_address a = Ipaddr.to_string a.Config.Address.ip ^ ":" ^ (string_of_int a.Config.Address.port)

type cb = request -> (response, [ `Msg of string ]) result Lwt.t

type message_cb = ?src:address -> ?dst:address -> buf:Cstruct.t -> unit -> unit Lwt.t

type t = {
  mutable cb: cb;
  client_address: address;
  server_address: address;
  message_cb: message_cb;
}

let rpc t request =
  let open Lwt.Infix in
  t.message_cb ~src:t.client_address ~dst:t.server_address ~buf:request ()
  >>= fun () ->
  t.cb request
  >>= function
  | Result.Ok response ->
      t.message_cb ~src:t.server_address ~dst:t.client_address ~buf:response ()
      >>= fun () ->
      Lwt.return (Result.Ok response)
  | Result.Error e ->
      Lwt.return (Result.Error e)

let nr_connects = Hashtbl.create 7

let get_connections () = Hashtbl.fold (fun k v acc -> (k, v) :: acc) nr_connects []

let disconnect t =
  let nr = Hashtbl.find nr_connects t.server_address - 1 in
  if nr = 0 then Hashtbl.remove nr_connects t.server_address else Hashtbl.replace nr_connects t.server_address nr;
  t.cb <- (fun _ -> Lwt.return (Result.Error (`Msg "disconnected")));
  Lwt.return_unit

type server = {
  mutable listen_cb: cb;
  address: address;
}
let bound = Hashtbl.create 7

let connect ~gen_transaction_id:_ ?(message_cb = (fun ?src:_ ?dst:_ ~buf:_ () -> Lwt.return_unit)) address =
  (* Use a fixed client address for now *)
  let client_address = { Config.Address.ip = Ipaddr.of_string_exn "1.2.3.4"; port = 32768 } in
  if Hashtbl.mem bound address then begin
    Hashtbl.replace nr_connects address (if Hashtbl.mem nr_connects address then Hashtbl.find nr_connects address else 1);
    let cb = (Hashtbl.find bound address).listen_cb in
    Lwt.return (Result.Ok { cb; client_address; server_address = address; message_cb })
  end else errorf "connect: no server bound to %s" (string_of_address address)

let bind address =
  let listen_cb _ = Lwt.return (Result.Error (`Msg "no callback")) in
  let server = { listen_cb; address } in
  if Hashtbl.mem bound address
  then Lwt.return (Result.Error (`Msg "address already bound"))
  else begin
    Hashtbl.replace bound address server;
    Lwt.return (Result.Ok server)
  end
let listen server cb =
  server.listen_cb <- cb;
  Lwt.return (Result.Ok ())
let shutdown server =
  server.listen_cb <- (fun _ -> Lwt.return (Result.Error (`Msg "shutdown")));
  Hashtbl.remove bound server.address;
  Lwt.return_unit

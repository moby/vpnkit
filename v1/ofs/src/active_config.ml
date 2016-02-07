open Protocol_9p
open Lwt
open Result

module Client = Client9p_unix.Make(Log9p_unix.Stdout)

type 'a values = Value of ('a * ('a values) Lwt.t)

let hd = function Value(first, _) -> first
let tl = function Value(_, next) -> next
let rec map f = function Value(first, next) ->
  f first
  >>= fun first' ->
  let next' =
    next
    >>= fun next ->
    map f next in
  return (Value(first', next'))
let changes values =
  let rec loop last next =
    next >>= function Value(first, next) ->
    if Some first = last
    then loop last next
    else return (Value(first, loop (Some first) next)) in
  loop None values

type t = {
  conn: Client.t;
  fid: Protocol_9p.Types.Fid.t;
  shas: string values;
}

(* very similar to functions in i9p/tests/test_utils *)

let ( >>*= ) x f =
  x >>= function
  | Ok y -> f y
  | Error (`Msg msg) -> Lwt.fail (Failure msg)

let ( ++ ) = Int64.add

let lines conn fid : string values Lwt.t =
  let rec loop ~saw_flush ~buf ~off =
    match String.index buf '\n' with
    | i ->
      let line = String.sub buf 0 i in
      let buf = String.sub buf (i + 1) (String.length buf - i - 1) in
      return (Value (line, loop ~saw_flush ~buf ~off))
    | exception Not_found ->
      Client.LowLevel.read conn fid off 256l >>*= fun resp ->
      match Cstruct.to_string resp.Protocol_9p.Response.Read.data with
      | "" when saw_flush -> Lwt.fail End_of_file
      | "" -> loop ~saw_flush:true ~buf ~off
      | data ->
          loop
            ~saw_flush:false
            ~buf:(buf ^ data)
            ~off:(off ++ Int64.of_int (String.length data)) in
  loop ~saw_flush:false ~buf:"" ~off:0L

let read conn path =
  let buffer = Buffer.create 128 in
  let rec loop ofs =
    Client.read conn path ofs 1024l
    >>*= fun bufs ->
    let n = List.fold_left (+) 0 (List.map Cstruct.len bufs) in
    if n = 0
    then return @@ Buffer.contents buffer
    else begin
      List.iter (fun x -> Buffer.add_string buffer (Cstruct.to_string x)) bufs;
      loop Int64.(add ofs (of_int n))
    end in
  Lwt.catch
    (fun () ->
      loop 0L
      >>= fun text ->
      return (Some text)
    ) (fun _ -> return None)

let rwx = [`Read; `Write; `Execute]
let rx = [`Read; `Execute]
let rwxr_xr_x = Protocol_9p.Types.FileMode.make ~owner:rwx ~group:rx ~other:rx ()

let create ?username proto address =
  Client.connect proto address ?username ()
  >>= function
  | Result.Error (`Msg x) -> failwith x
  | Result.Ok conn ->
    (* If we start first we need to create the master branch *)
    Client.mkdir conn ["branch"] "master" rwxr_xr_x
    >>*= fun () ->
    (* FIXME: the ocaml-9p client API is terrible *)
    let fid_t, fid_u = Lwt.task () in
    let _t = Client.with_fid conn (fun newfid ->
      Lwt.wakeup fid_u newfid; (* let it escape the scope *)
      fst @@ Lwt.task () (* never returns *)
    ) in
    fid_t >>= fun fid ->
    Client.walk_from_root conn fid ["branch"; "master"; "watch"; "tree.live"]
    >>*= fun _walk ->
    Client.LowLevel.openfid conn fid Protocol_9p.Types.OpenMode.read_only
    >>*= fun _openfid ->
    lines conn fid
    >>= fun shas ->
    Lwt.return { conn; fid; shas }

type path = string list

let string t path =
  changes @@ map (fun sha -> read t.conn ("trees" :: sha :: path)) t.shas

let int t path =
  string t path
  >>= fun strings ->
  let parse = function
    | None -> return None
    | Some s -> return (try Some (int_of_string s) with _ -> None) in
  changes @@ map parse strings

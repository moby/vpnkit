open Protocol_9p
open Lwt
open Result

let src =
  let src = Logs.Src.create "active_config" ~doc:"Database configuration values" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Client = Client9p_unix.Make(Log9p_unix.Stdout)

let ( >>*= ) x f =
  x >>= function
  | Ok y -> f y
  | Error (`Msg msg) -> Lwt.fail (Failure msg)

let ( >>|= ) x f =
  x >>= function
  | Ok y -> f y
  | Error (`Msg msg) -> Lwt.return (Error (`Msg msg))


type 'a values = Value of ('a * ('a values) Lwt.t)

let hd = function Value(first, _) -> first
let tl = function Value(_, next) -> next

let changes values =
  let rec loop last next =
    next >>= function Value(first, next) ->
    if Some first = last
    then loop last next
    else return (Value(first, loop (Some first) next)) in
  loop None values

module Transport = struct
  type t = {
    conn: Client.t;
    fid: Protocol_9p.Types.Fid.t;
    shas: string values;
  }

  (* very similar to functions in i9p/tests/test_utils *)

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

  let connect proto address ?username () =
    let log_every = 100 in (* 10s *)
    let rec loop ?(x="") n =
      if n = 0 then Log.err (fun f -> f "Failure connecting to db %S: %s" address x);
      let n = if n = 0 then log_every else n - 1 in
      Lwt.catch
        (fun () ->
          Client.connect proto address ?username ()
          >>= function
          | Result.Error (`Msg x) ->
            Lwt_unix.sleep 0.1
            >>= fun () ->
            loop ~x (n - 1)
          | Result.Ok conn ->
            Lwt.return conn
        ) (fun e ->
            Lwt_unix.sleep 0.1
            >>= fun () ->
            loop ~x:(Printexc.to_string e) (n - 1)
          ) in
    loop 1 (* if we fail straightaway, log the error *)

  let create ?username proto address =
    connect proto address ?username ()
    >>= fun conn ->
    Lwt.catch
      (fun () ->
        (* If we start first we need to create the master branch *)
        Client.mkdir conn ["branch"] "master" rwxr_xr_x
        >>|= fun () ->
        Client.LowLevel.allocate_fid conn
        >>|= fun fid ->
        Client.walk_from_root conn fid ["branch"; "master"; "watch"; "tree.live"]
        >>|= fun _walk ->
        Client.LowLevel.openfid conn fid Protocol_9p.Types.OpenMode.read_only
        >>|= fun _openfid ->
        lines conn fid
        >>= fun shas ->
        Lwt.return (Ok { conn; fid; shas })
      ) (fun e ->
        Client.disconnect conn
        >>= fun () ->
        Lwt.return (Error (`Msg ("Transport.create: " ^ (Printexc.to_string e))))
      )
end

type t = {
  proto: string;
  address: string;
  username: string option;
  mutable transport: Transport.t option;
  transport_m: Lwt_mutex.t;
}

let create ?username proto address =
  let transport = None in
  let transport_m = Lwt_mutex.create () in
  { proto; address; username; transport; transport_m }

let rec retry_forever f =
  f ()
  >>= function
  | Ok x -> Lwt.return x
  | Error (`Msg _) -> retry_forever f

(* Will retry forever to create a connected transport *)
let transport ({ username; proto; address } as t) =
  Lwt_mutex.with_lock t.transport_m
    (fun () ->
      match t.transport with
        | Some transport -> Lwt.return transport
        | None ->
          Log.info (fun f -> f "attempting to reconnect to database");
          retry_forever (fun () -> Transport.create ?username proto address)
          >>= fun transport ->
          Log.info (fun f -> f "reconnected transport layer");
          t.transport <- Some transport;
          Lwt.return transport
    )

let rec values t path =
  transport t
  >>= fun { Transport.conn; shas } ->
  let rec loop = function
  | Value(hd, tl_t) ->
    Transport.read conn ("trees" :: hd :: path)
    >>= fun v_opt ->
    let next =
      Lwt.catch
        (fun () -> tl_t >>= fun tl -> loop tl)
        (fun e ->
          if Lwt.state (Client.after_disconnect conn) <> Lwt.Sleep && t.transport <> None then begin
            t.transport <- None;
            Log.info (fun f -> f "transport layer has disconnected");
          end;
          values t path
        ) in
    Lwt.return (Value(v_opt, next )) in
  loop shas

let rec map f = function Value(first, next) ->
  f first
  >>= fun first' ->
  let next' =
    next
    >>= fun next ->
    map f next in
  return (Value(first', next'))

type path = string list

let string_option t path =
  changes @@ values t path
  
let string t ~default path =
  values t path
  >>= fun vs ->
  changes @@ map (function
    | None -> Lwt.return default
    | Some x -> Lwt.return x
  ) vs

let int t ~default path =
  string t ~default:(string_of_int default) path
  >>= fun strings ->
  let parse s = return (try int_of_string s with _ -> default) in
  changes @@ map parse strings

let bool t ~default path =
  string t ~default:(string_of_bool default) path
  >>= fun strings ->
  let parse s = return (try bool_of_string s with _ -> default) in
  changes @@ map parse strings

open Lwt.Infix
open Result
open Fs9p_error.Infix
module P = Protocol_9p

let src = Logs.Src.create "fs9p" ~doc:"VFS to 9p"

module Log = (val Logs.src_log src : Logs.LOG)

let pp_fid =
  let str x = P.Types.Fid.sexp_of_t x |> Sexplib.Sexp.to_string in
  Fmt.of_to_string str

type 'a or_err = 'a Protocol_9p.Error.t Lwt.t

let ok x = Lwt.return (Ok x)

let map_error x = Fs9p_error.map_error x

let error fmt = Fmt.kstrf (fun s -> Lwt.return (Fs9p_error.error "%s" s)) fmt

let err_not_a_dir name = error "%S is not a directory" name

let err_can't_set_length_of_dir = error "Can't set length of a directory"

let err_can't_walk_from_file = error "Can't walk from a file"

let err_can't_seek_dir = error "Can't seek in a directory"

let err_unknown_fid fid = error "Unknown fid %a" pp_fid fid

let err_fid_in_use fid = error "Fid %a already in use" pp_fid fid

let err_dot = error "'.' is not valid in 9p"

let err_read_not_open = error "Can't read from unopened fid"

let err_already_open = error "Already open"

let err_create_open = error "Can't create in an opened fid"

let err_write_not_open = error "Can't write to unopened fid"

let err_write_dir = error "Can't write to directories"

let err_rename_root = error "Can't rename /"

let err_multiple_updates = error "Can't rename/truncate/chmod at the same time"

let max_chunk_size = Int32.of_int (100 * 1024)

module type S = sig
  type flow

  val accept : root:Vfs.Dir.t -> msg:string -> flow -> unit or_err
end

(* 9p inodes: wrap VFS inodes with Qids. *)
module Inode = struct
  include Vfs.Inode

  (* All you can do with an open dir is list it *)
  type open_dir = { offset : int64; unread : t list }

  let _pp_open_dir ppf t =
    Fmt.pf ppf "offset:%Ld unread:[%a]" t.offset Fmt.(list pp) t.unread

  let offset t = t.offset

  let unread t = t.unread

  type fd = [ `OpenFile of Vfs.File.fd | `OpenDir of open_dir ]

  let qid t =
    match kind t with
    | `File _ -> P.Types.Qid.file ~id:(ino t) ~version:0l ()
    | `Dir _ -> P.Types.Qid.dir ~id:(ino t) ~version:0l ()
end

(* 9p operations. *)
module Op9p = struct
  let rwx = [ `Read; `Write; `Execute ]

  let rw = [ `Read; `Write ]

  let rx = [ `Read; `Execute ]

  let r = [ `Read ]

  let stat ~info inode =
    let ext ?extension () =
      (* Note: we always need an extension for the Unix protocol, or
         mortdeus will crash *)
      if info.P.Info.version <> P.Types.Version.unix then None
      else
        Some
          (P.Types.Stat.make_extension ?extension ~n_uid:0l ~n_gid:0l
             ~n_muid:0l ())
    in
    ( match Inode.kind inode with
    | `Dir _ ->
        let dir =
          P.Types.FileMode.make ~owner:rwx ~group:rwx ~other:rx
            ~is_directory:true ()
        in
        ok (0L, dir, ext ())
    | `File f ->
        Vfs.File.stat f >>= map_error >>*= fun info ->
        let file, u =
          match info.Vfs.perm with
          | `Normal ->
              (P.Types.FileMode.make ~owner:rw ~group:rw ~other:r (), ext ())
          | `Exec ->
              (P.Types.FileMode.make ~owner:rwx ~group:rwx ~other:rx (), ext ())
          | `Link target ->
              let u = ext ~extension:target () in
              ( P.Types.FileMode.make ~is_symlink:true ~owner:rwx ~group:rwx
                  ~other:rx (),
                u )
        in
        ok (info.Vfs.length, file, u) )
    >>*= fun (length, mode, u) ->
    let qid = Inode.qid inode in
    let name = Inode.basename inode in
    ok (P.Types.Stat.make ~qid ~mode ~length ~name ?u ())

  let rename dir inode new_name =
    match Inode.kind dir with
    | `File _ -> assert false
    | `Dir d ->
        Vfs.Dir.rename d inode new_name >>= map_error >>*= fun () ->
        Inode.set_basename inode new_name;
        ok ()

  let truncate inode length =
    match Inode.kind inode with
    | `Dir _ when length = 0L -> ok ()
    | `Dir _ -> err_can't_set_length_of_dir
    | `File f -> Vfs.File.truncate f length >>= map_error

  let mode_of_9p m ext =
    if m.P.Types.FileMode.is_directory then Ok `Dir
    else if m.P.Types.FileMode.is_symlink then
      match ext with
      | Some target -> Ok (`Link target)
      | None -> Fs9p_error.error "Missing target for symlink!"
    else if List.mem `Execute m.P.Types.FileMode.owner then Ok `Exec
    else Ok `Normal

  let chmod inode mode extension =
    Lwt.return (mode_of_9p mode extension) >>*= fun perm ->
    match (Inode.kind inode, perm) with
    | `Dir _, `Dir -> Lwt.return Vfs.Error.perm >>= map_error
    | `File f, (#Vfs.perm as perm) -> Vfs.File.chmod f perm >>= map_error
    | _ -> error "Incorrect is_directory flag for chmod"

  let read inode =
    match Inode.kind inode with
    | `File file ->
        Vfs.File.open_ file >>= map_error >>*= fun o ->
        ok (`OpenFile o)
    | `Dir dir ->
        Vfs.Dir.ls dir >>= map_error >>*= fun items ->
        ok (`OpenDir { Inode.offset = 0L; unread = items })

  let read_dir ~info ~offset ~count state =
    if offset <> Inode.offset state then err_can't_seek_dir
      (* TODO: allow 0 to restart *)
    else
      let buffer = Cstruct.create count in
      let rec aux buf = function
        | [] -> ok (buf, []) (* Done *)
        | x :: xs as items -> (
            stat ~info x >>*= fun x_info ->
            match P.Types.Stat.write x_info buf with
            | Ok buf -> aux buf xs
            | Error _ -> ok (buf, items) )
        (* No more room *)
      in
      aux buffer (Inode.unread state) >>*= fun (unused, remaining) ->
      let data = Cstruct.sub buffer 0 (count - Cstruct.len unused) in
      let len = Cstruct.len data in
      (* Linux will abort if we return an error. Instead, just return 0 items. Linux
         will free up space in its buffer and try again. *)
      (* if len = 0 && remaining <> [] then err_buffer_too_small *)
      let offset = Int64.add (Inode.offset state) (Int64.of_int len) in
      let new_state = { Inode.offset; unread = remaining } in
      ok (new_state, data)

  let create ~parent ~perm ~extension name =
    match Inode.kind parent with
    | `Dir d ->
        (Lwt.return (mode_of_9p perm extension) >>*= function
         | `Dir -> Vfs.Dir.mkdir d name >>= map_error
         | #Vfs.perm as perm -> Vfs.Dir.mkfile d ~perm name >>= map_error)
        >>*= fun inode ->
        read inode >>*= fun open_file ->
        ok (inode, open_file)
    | `File _ -> err_not_a_dir (Inode.basename parent)

  let remove inode =
    match Inode.kind inode with
    | `File f -> Vfs.File.remove f >>= map_error
    | `Dir d -> Vfs.Dir.remove d >>= map_error
end

module Make (Flow : Mirage_flow.S) = struct
  type flow = Flow.flow

  (** Handle incoming requests from the client. *)
  module Dispatcher = struct
    type fd = {
      inode : Inode.t;
      parents : Inode.t list;
      (* closest first *)
      mutable state : [ `Ready | Inode.fd ];
    }

    type t = Vfs.Dir.t (* The root directory *)

    type connection = {
      root : t;
      info : Protocol_9p.Info.t;
      mutable fds : fd P.Types.Fid.Map.t;
    }

    let connect root info =
      let fds = P.Types.Fid.Map.empty in
      { root; info; fds }

    let lookup connection fid =
      try ok (P.Types.Fid.Map.find fid connection.fds)
      with Not_found -> err_unknown_fid fid

    let alloc_fid ?may_reuse connection newfid fd =
      let alloc () =
        connection.fds <- P.Types.Fid.Map.add newfid fd connection.fds;
        ok ()
      in
      match may_reuse with
      | Some old when old = newfid -> alloc ()
      | Some _ | None ->
          if P.Types.Fid.Map.mem newfid connection.fds then
            err_fid_in_use newfid
          else alloc ()

    (* Returns the final inode, the path that led to it, and the new parents. *)
    let rec do_walk ~parents ~wqids inode = function
      | [] -> ok (inode, List.rev wqids, parents)
      | x :: xs -> (
          match Inode.kind inode with
          | `File _ -> err_can't_walk_from_file
          | `Dir dir ->
              ( match x with
              | "." -> err_dot
              | ".." -> (
                  match parents with
                  | [] -> ok (inode, parents) (* /.. = / *)
                  | p :: ps -> ok (p, ps) )
              | x ->
                  Vfs.Dir.lookup dir x >>= map_error >>*= fun x_inode ->
                  ok (x_inode, inode :: parents) )
              >>*= fun (inode, parents) ->
              let wqids = Inode.qid inode :: wqids in
              do_walk ~parents ~wqids inode xs )

    let walk connection ~cancel:_ { P.Request.Walk.fid; newfid; wnames } =
      lookup connection fid >>*= fun fd ->
      do_walk ~parents:fd.parents ~wqids:[] fd.inode wnames
      >>*= fun (inode, wqids, parents) ->
      let fd = { inode; parents; state = `Ready } in
      alloc_fid ~may_reuse:fid connection newfid fd >>*= fun () ->
      ok { P.Response.Walk.wqids }

    let attach connection ~cancel:_ { P.Request.Attach.fid; _ } =
      let fd =
        { inode = Inode.dir "/" connection.root; parents = []; state = `Ready }
      in
      alloc_fid connection fid fd >>*= fun () ->
      ok { P.Response.Attach.qid = Inode.qid fd.inode }

    let clunk_fid connection fid =
      connection.fds <- P.Types.Fid.Map.remove fid connection.fds

    let clunk connection ~cancel:_ { P.Request.Clunk.fid } =
      let old = connection.fds in
      clunk_fid connection fid;
      if connection.fds == old then error "Unknown fid %a" pp_fid fid
      else ok ()

    let stat connection ~cancel:_ { P.Request.Stat.fid } =
      lookup connection fid >>*= fun fd ->
      Op9p.stat ~info:connection.info fd.inode >>*= fun stat ->
      ok { P.Response.Stat.stat }

    let read connection ~cancel:_ { P.Request.Read.fid; offset; count } =
      let count = Int32.to_int (min count max_chunk_size) in
      lookup connection fid >>*= fun fd ->
      match fd.state with
      | `Ready -> err_read_not_open
      | `OpenFile file ->
          Vfs.File.read file ~offset ~count >>= map_error >>*= fun data ->
          ok { P.Response.Read.data }
      | `OpenDir d ->
          Op9p.read_dir ~info:connection.info ~offset ~count d
          >>*= fun (new_state, data) ->
          fd.state <- `OpenDir new_state;
          ok { P.Response.Read.data }

    let open_ connection ~cancel:_ { P.Request.Open.fid; _ } =
      lookup connection fid >>*= fun fd ->
      match fd.state with
      | `OpenDir _ | `OpenFile _ -> err_already_open
      | `Ready ->
          Op9p.read fd.inode >>*= fun state ->
          fd.state <- state;
          ok { P.Response.Open.qid = Inode.qid fd.inode; iounit = 0l }

    let create connection ~cancel:_
        { P.Request.Create.fid; perm; name; extension; _ } =
      lookup connection fid >>*= fun fd ->
      if fd.state <> `Ready then err_create_open
      else
        Op9p.create ~parent:fd.inode ~perm ~extension name
        >>*= fun (inode, open_file) ->
        let fd =
          { inode; parents = fd.inode :: fd.parents; state = open_file }
        in
        connection.fds <- P.Types.Fid.Map.add fid fd connection.fds;
        ok { P.Response.Create.qid = Inode.qid inode; iounit = 0l }

    let write connection ~cancel:_ { P.Request.Write.fid; offset; data } =
      lookup connection fid >>*= fun fd ->
      match fd.state with
      | `Ready -> err_write_not_open
      | `OpenDir _ -> err_write_dir
      | `OpenFile file ->
          Vfs.File.write file ~offset data >>= map_error >>*= fun () ->
          let count = Int32.of_int (Cstruct.len data) in
          ok { P.Response.Write.count }

    let remove connection ~cancel:_ { P.Request.Remove.fid } =
      lookup connection fid >>*= fun fd ->
      Op9p.remove fd.inode >|= fun err ->
      clunk_fid connection fid;
      err

    let rename fd name =
      match fd.parents with
      | [] -> err_rename_root
      | p :: _ -> Op9p.rename p fd.inode name

    let get_ext = function
      | None -> None
      | Some ext -> Some ext.P.Types.Stat.extension

    let wstat connection ~cancel:_ { P.Request.Wstat.fid; stat } =
      lookup connection fid >>*= fun fd ->
      let { P.Types.Stat.name; length; mtime; gid; mode; u; _ } = stat in
      (* It's illegal to set [ty], [dev], [qid], [atime], [uid],
         [muid] and [u], but checking if we're setting to the current
         value is tedious, so ignore: *)
      ignore mtime;

      (* Linux needs to set mtime *)
      ignore gid;

      (* We don't care about permissions *)
      let name = if name = "" then None else Some name in
      let length = if P.Types.Int64.is_any length then None else Some length in
      let mode = if P.Types.FileMode.is_any mode then None else Some mode in
      match (name, length, mode) with
      | Some n, None, None -> rename fd n
      | None, Some l, None -> Op9p.truncate fd.inode l
      | None, None, Some m -> Op9p.chmod fd.inode m (get_ext u)
      | None, None, None -> ok ()
      | _ ->
          (* Hard to support atomically, and unlikely to be useful. *)
          err_multiple_updates
  end

  module Server = P.Server.Make (Log) (Flow) (Dispatcher)

  let accept ~root ~msg flow =
    Log.info (fun l -> l "accepted a new connection on %s" msg);
    Server.connect root flow () >>= function
    | Error _ as e ->
        Flow.close flow >|= fun () ->
        e
    | Ok t ->
        (* Close the flow when the 9P connection shuts down *)
        Server.after_disconnect t >>= fun () ->
        Flow.close flow >>= fun () ->
        ok ()
end

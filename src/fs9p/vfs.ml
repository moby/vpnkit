open Astring
open Rresult
open Lwt.Infix

type perm = [ `Normal | `Exec | `Link of string ]

type metadata = { length : int64; perm : perm }

module Error = struct
  type err = { errno : int32 option; descr : string }

  type t = Noent | Isdir | Notdir | Read_only_file | Perm | Other of err

  let otherk k ?errno fmt =
    Printf.ksprintf (fun descr -> k (Error (Other { descr; errno }))) fmt

  let other ?errno fmt = otherk (fun e -> e) ?errno fmt

  let no_entry = Error Noent

  let is_dir = Error Isdir

  let not_dir = Error Notdir

  let read_only_file = Error Read_only_file

  let perm = Error Perm

  let negative_offset o = other "Negative offset %Ld" o

  let offset_too_large ~offset l =
    other "Offset %Ld beyond end-of-file (len = %Ld)" offset l

  module Infix = struct
    open Lwt.Infix

    let ( >>*= ) x f =
      x >>= function Ok x -> f x | Error _ as e -> Lwt.return e
  end

  let pp f = function
    | Noent -> Fmt.string f "No such file or directory"
    | Isdir -> Fmt.string f "The entry is a directory"
    | Notdir -> Fmt.string f "The entry is not a directory"
    | Read_only_file -> Fmt.string f "The file is read-only"
    | Perm -> Fmt.string f "The operation is not permitted"
    | Other err -> Fmt.string f err.descr
end

open Error.Infix

let ok x = Lwt.return (Ok x)

let error fmt = Error.otherk Lwt.return fmt

type 'a or_err = ('a, Error.t) Result.result Lwt.t

module File = struct
  let err_no_entry = Lwt.return Error.no_entry

  let err_read_only = Lwt.return Error.read_only_file

  let err_perm = Lwt.return Error.perm

  let err_bad_write_offset off = error "Bad write offset %d" off

  let err_stream_seek = error "Attempt to seek in stream"

  let err_extend_cmd_file = error "Can't extend command file"

  let err_normal_only = error "Can't chmod special file"

  let ok x = Lwt.return (Ok x)

  let check_offset ~offset len =
    if offset < 0L then Lwt.return (Error.negative_offset offset)
    else if offset > Int64.of_int len then
      Lwt.return (Error.offset_too_large ~offset (Int64.of_int len))
    else ok ()

  let empty = Cstruct.create 0

  module Stream = struct
    type t = {
      read : int -> Cstruct.t or_err;
      write : Cstruct.t -> unit or_err;
    }

    let read t = t.read

    let write t = t.write

    type 'a session = { mutable v : 'a; c : unit Lwt_condition.t }

    let session v = { v; c = Lwt_condition.create () }

    let publish session v =
      session.v <- v;
      Lwt_condition.broadcast session.c ()

    let create pp session =
      (* [buffer] is the remainder of the line we're currently sending to the client.
         [last] is the whole line (to avoid sending the same line twice).
         When [data] is empty, we wait until [session]'s value is no longer [last] and
         use that as the next [buffer].
         [!buffer] is a thread in case the client does two reads at the same time,
         although that doesn't make much sense for streams anyway. *)
      let last = ref (Fmt.to_to_string pp session.v) in
      let buffer = ref (Lwt.return (Cstruct.of_string !last)) in
      let refill () =
        let rec next () =
          let current = Fmt.to_to_string pp session.v in
          if current = !last then Lwt_condition.wait session.c >>= next
          else (
            last := current;
            Lwt.return (Cstruct.of_string current) )
        in
        buffer := next ()
      in
      let rec read count =
        !buffer >>= fun avail ->
        if Cstruct.len avail = 0 then (
          refill ();
          read count )
        else
          let count = min count (Cstruct.len avail) in
          let response = Cstruct.sub avail 0 count in
          buffer := Lwt.return (Cstruct.shift avail count);
          Lwt.return (Ok response)
      in
      let write _ = err_read_only in
      { read; write }
  end

  module Fd = struct
    type t = {
      read : offset:int64 -> count:int -> Cstruct.t or_err;
      write : offset:int64 -> Cstruct.t -> unit or_err;
    }

    let create ~read ~write = { read; write }

    let read t = t.read

    let write t = t.write

    let static data =
      let read ~offset ~count =
        check_offset ~offset (Cstruct.len data) >>*= fun () ->
        let avail = Cstruct.shift data (Int64.to_int offset) in
        let count = min count (Cstruct.len avail) in
        ok (Cstruct.sub avail 0 count)
      in
      let write ~offset:_ _data = err_read_only in
      ok { read; write }

    let ( ++ ) = Int64.add

    let of_stream stream =
      let current_offset = ref 0L in
      let need_flush = ref false in
      (* Linux requires a blocking read to return "" to indicate that it
         is blocking. Otherwise, it doesn't return the existing data to
         the application. To Linux, two "" in a row means end-of-file.
         Other systems will probably interpret a single "" as end-of-file.
         Oh well. *)
      (* TODO: prevent concurrent reads/writes *)
      let read ~offset ~count =
        if offset <> !current_offset then err_stream_seek
        else if !need_flush then (
          need_flush := false;
          ok empty )
        else
          Stream.read stream count >>*= fun result ->
          current_offset :=
            !current_offset ++ Int64.of_int (Cstruct.len result);
          need_flush := true;
          ok result
      in
      let write ~offset data =
        if offset <> !current_offset then err_stream_seek
        else
          Stream.write stream data >>*= fun () ->
          current_offset := !current_offset ++ Int64.of_int (Cstruct.len data);
          ok ()
      in
      ok { read; write }
  end

  type fd = Fd.t

  let create_fd = Fd.create

  let read = Fd.read

  let write = Fd.write

  type t = {
    debug : string;
    stat : unit -> metadata or_err;
    open_ : unit -> fd or_err;
    remove : unit -> unit or_err;
    truncate : int64 -> unit or_err;
    chmod : perm -> unit or_err;
  }

  let pp ppf t = Fmt.pf ppf "Vfs.File.%s" t.debug

  let create_aux ~debug ~stat ~open_ ~remove ~truncate ~chmod =
    { debug; stat; open_; remove; truncate; chmod }

  let stat t = t.stat ()

  let size t =
    stat t >>*= fun info ->
    Lwt.return (Ok info.length)

  let open_ t = t.open_ ()

  let remove t = t.remove ()

  let truncate t = t.truncate

  let chmod t = t.chmod

  let read_only_aux =
    create_aux
      ~remove:(fun _ -> err_read_only)
      ~truncate:(fun _ -> err_read_only)
      ~chmod:(fun _ -> err_read_only)

  let ro_of_cstruct ?(perm = `Normal) data =
    let length = Cstruct.len data |> Int64.of_int in
    let stat () = ok { length; perm } in
    let open_ () = Fd.static data in
    read_only_aux ~stat ~open_

  let ro_of_string ?perm text =
    ro_of_cstruct ~debug:"ro_of_string" ?perm (Cstruct.of_string text)

  let of_stream stream =
    let stat () = ok { length = 0L; perm = `Normal } in
    let open_ () =
      stream () >>= fun s ->
      Fd.of_stream s
    in
    read_only_aux ~debug:"of_stream" ~stat ~open_

  let normal_only = function
    | `Normal -> ok ()
    | `Exec | `Link _ -> err_normal_only

  let command ?(init = "") handler =
    (* Value currently being returned to user. Note that this is
       attached to the file, not the client's FD. This is so a shell
       client can write and then read in a separate step, but does
       mean we can't support parallel commands for a single FS (so if
       this is used, you should create a fresh FS for each client
       connection at least). *)
    let data = ref (Cstruct.of_string init) in
    let stat () =
      let length = Int64.of_int @@ Cstruct.len !data in
      ok { length; perm = `Normal }
    in
    let open_ () =
      let read count =
        let count = min count (Cstruct.len !data) in
        let result = Cstruct.sub !data 0 count in
        data := Cstruct.shift !data count;
        ok result
      in
      let write buf =
        handler @@ String.trim (Cstruct.to_string buf) >>*= fun result ->
        data := Cstruct.of_string result;
        ok ()
      in
      let stream = { Stream.read; write } in
      Fd.of_stream stream
    in
    let remove () = err_perm in
    let truncate = function
      | 0L -> ok () (* For `echo cmd > file` *)
      | _ -> err_extend_cmd_file
    in
    create_aux ~debug:"command" ~stat ~open_ ~remove ~truncate
      ~chmod:normal_only

  let status ?length fn =
    let stat () =
      let length =
        match length with
        | None ->
            fn () >|= fun data ->
            String.length data
        | Some f -> f ()
      in
      length >|= fun length ->
      Ok { length = length |> Int64.of_int; perm = `Normal }
    in
    let open_ () =
      let data =
        fn () >|= fun result ->
        ref (Cstruct.of_string result)
      in
      let read count =
        data >>= fun data ->
        let count = min count (Cstruct.len !data) in
        let result = Cstruct.sub !data 0 count in
        data := Cstruct.shift !data count;
        ok result
      in
      let write _ = err_read_only in
      let stream = { Stream.read; write } in
      Fd.of_stream stream
    in
    read_only_aux ~debug:"status" ~stat ~open_

  (* [overwrite orig (new, offset)] is a buffer [start; padding; new;
      end] where [new] is at position [offset], [start] and [end] are
      from [orig] and [padding] is zeroes inserted as needed. *)
  let overwrite orig (data, offset) =
    let orig = match orig with None -> empty | Some orig -> orig in
    let orig_len = Cstruct.len orig in
    let data_len = Cstruct.len data in
    if offset = 0 && data_len >= orig_len then data (* Common, fast case *)
    else
      let padding = Cstruct.create (max 0 (offset - orig_len)) in
      let tail =
        let data_end = offset + data_len in
        if orig_len > data_end then
          Cstruct.sub orig data_end (orig_len - data_end)
        else empty
      in
      Cstruct.concat
        [ Cstruct.sub orig 0 (min offset (Cstruct.len orig));
          padding;
          data;
          tail
        ]

  let of_kv_aux ~read ~write ~stat ~remove ~chmod =
    let open_ () =
      let read ~offset ~count =
        read () >>*= function
        | None -> err_no_entry
        | Some contents ->
            check_offset ~offset (Cstruct.len contents) >>*= fun () ->
            let avail = Cstruct.shift contents (Int64.to_int offset) in
            let count = min count (Cstruct.len avail) in
            ok (Cstruct.sub avail 0 count)
      and write ~offset data =
        let offset = Int64.to_int offset in
        if offset < 0 then err_bad_write_offset offset
        else
          read () >>*= fun old ->
          write (overwrite old (data, offset))
      in
      ok @@ Fd.create ~read ~write
    in
    let truncate len =
      let len = Int64.to_int len in
      if len = 0 then write empty
      else
        read () >>*= fun old ->
        let old = match old with None -> empty | Some old -> old in
        let extra = len - Cstruct.len old in
        if extra = 0 then Lwt.return (Ok ())
        else if extra < 0 then write (Cstruct.sub old 0 len)
        else
          let padding = Cstruct.create extra in
          write (Cstruct.append old padding)
    in
    create_aux ~stat ~open_ ~truncate ~remove ~chmod

  let of_kvro ~read =
    let write _ = err_read_only in
    let remove () = err_read_only in
    let chmod _ = err_read_only in
    of_kv_aux ~debug:"of_kvro" ~read ~write ~remove ~chmod

  let rw_of_string init =
    let data = ref (Cstruct.of_string init) in
    let stat () =
      let length = Int64.of_int (Cstruct.len !data) in
      Lwt.return (Ok { length; perm = `Normal })
    in
    let read () = ok (Some !data) in
    let write v =
      data := v;
      ok ()
    in
    let remove () = err_read_only in
    let file =
      of_kv_aux ~debug:"rw_of_string" ~read ~write ~remove ~stat
        ~chmod:normal_only
    in
    (file, fun () -> Cstruct.to_string !data)

  let create = create_aux ~debug:"create"

  let of_kv = of_kv_aux ~debug:"of_kv"

  let stat_of ~read () =
    read () >>*= function
    | None -> err_no_entry
    | Some data ->
        ok { length = Int64.of_int (Cstruct.len data); perm = `Normal }
end

module Dir = struct
  let err_read_only = error "Directory is read-only"

  let err_already_exists = error "Already exists"

  let err_dir_only = error "Can only contain directories"

  let err_no_entry = Lwt.return Error.no_entry

  type t = {
    debug : string;
    ls : unit -> inode list or_err;
    mkfile : string -> perm -> inode or_err;
    lookup : string -> inode or_err;
    mkdir : string -> inode or_err;
    remove : unit -> unit or_err;
    rename : inode -> string -> unit or_err;
  }

  and kind = [ `File of File.t | `Dir of t ]

  and inode = { mutable basename : string; kind : kind; ino : int64 }

  let pp ppf t = Fmt.pf ppf "Vfs.Dir.%s" t.debug

  let pp_kind ppf k =
    Fmt.string ppf (match k with `Dir _ -> "dir" | `File _ -> "file")

  let pp_inode ppf t = Fmt.pf ppf "%s:%a[%Ld]" t.basename pp_kind t.kind t.ino

  let ls t = t.ls ()

  let mkfile t ?(perm = `Normal) name = t.mkfile name perm

  let lookup t = t.lookup

  let mkdir t = t.mkdir

  let remove t = t.remove ()

  let rename t = t.rename

  let create_aux ~debug ~ls ~mkfile ~lookup ~mkdir ~remove ~rename =
    { debug; ls; mkfile; mkdir; remove; lookup; rename }

  let read_only_aux =
    let mkfile _ _ = err_read_only in
    let mkdir _ = err_read_only in
    let rename _ _ = err_read_only in
    create_aux ~mkfile ~mkdir ~rename

  let of_list_aux items =
    let ls () = items () in
    let lookup name =
      let rec aux = function
        | [] -> err_no_entry
        | x :: _ when x.basename = name -> ok x
        | _ :: xs -> aux xs
      in
      items () >>*= aux
    in
    let remove () = err_read_only in
    read_only_aux ~ls ~lookup ~remove

  let empty = of_list_aux ~debug:"empty" (fun () -> ok [])

  let of_map_ref m =
    let ls () = ok (String.Map.bindings !m |> List.map snd) in
    let lookup name =
      match String.Map.find name !m with
      | Some x -> ok x
      | None -> err_no_entry
    in
    let remove () = err_read_only in
    read_only_aux ~debug:"of_map_ref" ~ls ~lookup ~remove

  let dir_only =
    let mkfile _ _ = err_dir_only in
    create_aux ~debug:"dir_only" ~mkfile

  let of_list = of_list_aux ~debug:"of_list"

  let create = create_aux ~debug:"create"

  let read_only = read_only_aux ~debug:"read_only"
end

module Inode = struct
  type t = Dir.inode

  let pp = Dir.pp_inode

  type kind = Dir.kind

  let mint_ino =
    let last = ref 0L in
    fun () ->
      let next = Int64.succ !last in
      last := next;
      next

  let file basename file =
    { Dir.basename; kind = `File file; ino = mint_ino () }

  let dir basename dir = { Dir.basename; kind = `Dir dir; ino = mint_ino () }

  let basename t = t.Dir.basename

  let set_basename t b = t.Dir.basename <- b

  let ino t = t.Dir.ino

  let kind t = t.Dir.kind
end

module Logs = struct
  let level s =
    (* [empty] should really be per-open-file, but no easy way to do that. *)
    let empty = ref false in
    let read () =
      if !empty then ok (Some (Cstruct.create 0))
      else
        let l = Logs.Src.level s in
        ok (Some (Cstruct.of_string (Logs.level_to_string l ^ "\n")))
    in
    let write data =
      match String.trim (Cstruct.to_string data) with
      | "" ->
          empty := true;
          ok ()
      | data -> (
          empty := false;
          match Logs.level_of_string data with
          | Ok l ->
              Logs.Src.set_level s l;
              ok ()
          | Error (`Msg msg) -> error "%s" msg )
    in
    let chmod _ = Lwt.return Error.perm in
    let remove () = Lwt.return Error.perm in
    File.of_kv ~read ~write ~stat:(File.stat_of ~read) ~remove ~chmod

  let src s =
    let items =
      [ Inode.file "doc" (File.ro_of_string (Logs.Src.doc s ^ "\n"));
        Inode.file "level" (level s)
      ]
    in
    Dir.of_list (fun () -> ok items)

  let srcs =
    let logs = Hashtbl.create 100 in
    let get_dir s =
      let name = Logs.Src.name s in
      try Hashtbl.find logs name
      with Not_found ->
        let dir = Inode.dir name (src s) in
        Hashtbl.add logs name dir;
        dir
    in
    Dir.of_list (fun () -> Logs.Src.list () |> List.map get_dir |> ok)

  let dir =
    let dirs = ok [ Inode.dir "src" srcs ] in
    Dir.of_list (fun () -> dirs)
end

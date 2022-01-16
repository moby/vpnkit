open Lwt.Infix

let src =
  let src = Logs.Src.create "ofs" ~doc:"active_list" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Var = struct

  type 'a t = {
    mutable thing: 'a option;
    c: unit Lwt_condition.t;
  }

  let create () =
    let c = Lwt_condition.create () in
    { thing = None; c }

  let fill t thing =
    t.thing <- Some thing;
    Lwt_condition.broadcast t.c ()

  let read t =
    let rec loop () = match t.thing with
    | Some c -> Lwt.return c
    | None   -> Lwt_condition.wait t.c >>= loop
    in
    loop ()

end

module type Instance = sig
  type t
  val to_string: t -> string
  val of_string: string -> (t, [ `Msg of string ]) result

  val description_of_format: string

  val start: t -> (t, [ `Msg of string ]) result Lwt.t

  val stop: t -> unit Lwt.t

  type key
  val get_key: t -> key
end

module StringMap = Map.Make(String)

module Make (Instance: Instance) = struct
  open Protocol_9p

  type t = unit

  let make () = ()

  (* We manage a list of named entries *)
  type entry = {
    name: string;
    mutable instance: Instance.t option;
    mutable result: string option;
  }

  let active : entry StringMap.t ref = ref StringMap.empty

  type resource =
    | ControlFile of entry
    | README
    | Entry of entry
    | Root

  let string_of_resource = function
  | ControlFile entry -> Printf.sprintf "ControlFile(%s)" entry.name
  | README -> "README"
  | Entry entry -> Printf.sprintf "Entry(%s)" entry.name
  | Root -> "Root"

  type connection = {
    t: t;
    fids: resource Types.Fid.Map.t ref;
  }

  let connect t _ = {
    t;
    fids = ref (Types.Fid.Map.empty);
  }

  module Error = struct
    let badfid = Lwt.return (Response.error "fid not found")
    let enoent = Lwt.return (Response.error "file not found")
    let eperm  = Lwt.return (Response.error "permission denied")
  end

  let qid_path = ref 0_L

  let next_qid flags =
    let id = !qid_path in
    qid_path := Int64.(add one !qid_path);
    Protocol_9p.Types.Qid.({ flags; version = 0_l; id; })

  let root_qid = next_qid [ Types.Qid.Directory ]

  let readme = Cstruct.of_string (Printf.sprintf {|
Directory of active Instances
-----------------------------

Every active Instance is represented by a file. To shut down an Instance,
remove the file.

To request an additional Instance, make a directory with a unique name,
then open the special file `ctl` inside, and `write` a single string of the
following form:

%s

Immediately read the file contents and check whether it says:

- `OK <instance details>`: this means the Instance has been configured and
  the details returned to you. For some instance types the server might modify
  the request slightly, for example by choosing a local port number or
  temporary path.
- `ERROR some error message`: this means the Instance creation has failed,
  perhaps some needed resource is still in use.

The directory will be deleted and replaced with a file of the same name.
|} Instance.description_of_format)

  let return x = Lwt.return (Ok x)

  let attach connection ~cancel:_ { Request.Attach.fid; _ } =
    connection.fids := Types.Fid.Map.add fid Root !(connection.fids);
    return { Response.Attach.qid = root_qid }

  exception Enoent

  let walk connection ~cancel:_ { Request.Walk.fid; newfid; wnames } =
    try
      let from = Types.Fid.Map.find fid !(connection.fids) in
      let from, wqids = List.fold_left (fun (from,qids) x ->
          match x, fst from with
          | "..", _ ->
            (Root, root_qid), root_qid::qids
          | "README", _ ->
            let qid = next_qid [] in
            (README, qid), qid :: qids
          | name, Root ->
            if StringMap.mem name !active then begin
              let entry = StringMap.find name !active in
              let qid = next_qid (match entry.instance with
                | None -> [ Types.Qid.Directory ]
                | Some _ -> []
                ) in
              (Entry entry, qid), qid :: qids
            end else raise Enoent
          | "ctl", Entry entry ->
            let qid = next_qid [] in
            (ControlFile entry, qid), qid :: qids
          | _, _ -> raise Enoent
        ) ((from, next_qid []), []) wnames
      in
      connection.fids := Types.Fid.Map.add newfid (fst from) !(connection.fids);
      let wqids = List.rev wqids in
      return { Response.Walk.wqids }
    with
    | Not_found -> Error.badfid
    | Enoent -> Error.enoent

  let free_resource = function
  | ControlFile entry ->
    Log.debug (fun f -> f "freeing entry %s" entry.name);
    let open Lwt.Infix in
    ( match entry.instance with
    | None -> Lwt.return ()
    | Some f -> Instance.stop f )
    >>= fun () ->
    entry.instance <- None;
    active := StringMap.remove entry.name !active;
    Lwt.return ()
  | _ ->
    Lwt.return ()

  let clunk connection ~cancel:_ { Request.Clunk.fid } =
    let open Lwt.Infix in
    ( if Types.Fid.Map.mem fid !(connection.fids) then begin
          let resource = Types.Fid.Map.find fid !(connection.fids) in
          free_resource resource
        end else Lwt.return () )
    >>= fun () ->
    connection.fids := Types.Fid.Map.remove fid !(connection.fids);
    return ()

  let open_ _connection ~cancel:_ _ =
    try
      let qid = next_qid [] in
      let iounit = 32768_l in
      return { Response.Open.qid; iounit }
    with Not_found -> Error.badfid

  let make_stat ~is_directory ~writable ~name =
    let exec = if is_directory then [ `Execute ] else [] in
    let perms =
      `Read :: (if writable then [ `Write ] else [] ) @ exec in
    let qid = next_qid [] in
    Types.({
        Stat.ty = 0xFFFF;
        dev     = Int32.(neg one);
        qid     = qid;
        mode    = FileMode.make
            ~owner:perms ~group:perms ~other:perms ~is_directory ();
        atime   = 1146711721l;
        mtime   = 1146711721l;
        length  = 0_L; (* TODO: wrong for regular files *)
        name    = name;
        uid     = "uid";
        gid     = "gid";
        muid    = "muid";
        u       = None;
      })

  let read_children count offset children =
    let buf = Cstruct.create count in
    let rec write off rest = function
    | [] -> return off
    | stat :: xs ->
      let open Infix in
      let n = Types.Stat.sizeof stat in
      if off < offset
      then write (off + n) rest xs
      else if Cstruct.len rest < n then return off
      else
        Lwt.return (Types.Stat.write stat rest)
        >>*= fun rest ->
        write (off + n) rest xs in
    let open Lwt.Infix in
    write 0 buf children
    >>= function
    | Ok offset' ->
      let data = Cstruct.sub buf 0 (max 0 (offset' - offset)) in
      return { Response.Read.data }
    | Error _ -> Error.badfid

  let dot = make_stat ~is_directory:true ~writable:false ~name:"."
  let dotdot = make_stat ~is_directory:true ~writable:false ~name:".."

  let read_string count offset message =
    let data = Cstruct.create (String.length message) in
    Cstruct.blit_from_string message 0 data 0 (String.length message);
    let len = min count Cstruct.(len data - offset) in
    let data = Cstruct.sub data offset len in
    return { Response.Read.data }

  let read connection ~cancel:_ { Request.Read.fid; offset; count } =
    let count = Int32.to_int count in
    let offset = Int64.to_int offset in
    try
      let resource = Types.Fid.Map.find fid !(connection.fids) in
      match resource with
      | ControlFile entry ->
        let message = match entry.result with
        | None -> "ERROR no request received. Please read the README.\n"
        | Some x -> x in
        read_string count offset message
      | README ->
        let len = min count Cstruct.(len readme - offset) in
        let data = Cstruct.sub readme offset len in
        return { Response.Read.data }
      | Entry { instance = Some i; _ } ->
        let i' = Instance.to_string i in
        read_string count offset (i' ^ "\n")
      | Entry { instance = None; _ } ->
        let children =
          dot
          :: dotdot
          :: [ make_stat ~is_directory:false ~writable:false ~name:"ctl" ] in
        read_children count offset children
      | Root ->
        let children =
          dot
          :: dotdot
          :: make_stat ~is_directory:false ~writable:false ~name:"README"
          :: (StringMap.fold (fun name entry acc ->
              let is_directory = match entry.instance with
              | None -> true
              | Some _ -> false in
              make_stat ~is_directory ~writable:false ~name
              :: acc) !active []) in
        read_children count offset children
    with Not_found -> Error.badfid

  let stat connection ~cancel:_ { Request.Stat.fid } =
    try
      let resource = Types.Fid.Map.find fid !(connection.fids) in
      let stat = match resource with
      | Root -> make_stat ~is_directory:true ~writable:true ~name:""
      | README -> make_stat ~is_directory:false ~writable:false ~name:"README"
      | ControlFile _ ->
        make_stat ~is_directory:false ~writable:true ~name:"ctl"
      | Entry { name; instance = None; _ } ->
        make_stat ~is_directory:true ~writable:false ~name
      | Entry { name; instance = Some _; _ } ->
        make_stat ~is_directory:false ~writable:false ~name in
      return { Response.Stat.stat }
    with Not_found -> Error.badfid

  let create connection ~cancel:_ { Request.Create.fid; name; perm; _ } =
    let resource = Types.Fid.Map.find fid !(connection.fids) in
    match resource with
    | Root when perm.Types.FileMode.is_directory ->
      let qid = next_qid [ Types.Qid.Directory ] in
      let entry = { name; instance = None; result = None } in
      active := StringMap.add name entry !active;
      let resource = Entry entry in
      connection.fids :=  Types.Fid.Map.add fid resource !(connection.fids);
      Log.debug (fun f -> f "Creating resource %s" (string_of_resource resource));
      return { Response.Create.qid; iounit = 512l }
    | resource ->
      Log.err (fun f -> f "EPERM creating resource = %s"
                  (string_of_resource resource));
      Error.eperm

  let write connection ~cancel:_ { Request.Write.fid; offset; data } =
    Log.debug (fun f ->
        f "Write offset=%Ld data=[%s] to file" offset (Cstruct.to_string data));
    let ok = { Response.Write.count = Int32.of_int @@ Cstruct.len data } in
    try
      let resource = Types.Fid.Map.find fid !(connection.fids) in
      match resource with
      | ControlFile entry ->
        if entry.result <> None then begin
          Log.err (fun f ->
              f "EPERM writing to an already-configured control file");
          Error.eperm
        end else begin match Instance.of_string @@ Cstruct.to_string data with
        | Ok f ->
          let open Lwt.Infix in
          begin Instance.start f >>=
            function
            | Ok f' -> (* local_port is resolved *)
              entry.instance <- Some f';
              entry.result <- Some ("OK " ^ (Instance.to_string f') ^ "\n");
              Log.debug (fun f ->
                  f "Created instance %s" (Instance.to_string f'));
              return ok
            | Error (`Msg m) ->
              entry.result <- Some ("ERROR " ^ m ^ "\n");
              return ok
          end
        | Error (`Msg m) ->
          Log.err (fun f ->
              f "Return an error message via the control file: %s" m);
          entry.result <- Some ("ERROR " ^ m ^ "\n");
          return ok
        end
      | _ ->
        Log.err (fun f ->
            f "EPERM writing to resource %s" (string_of_resource resource));
        Error.eperm
    with Not_found ->
      Log.err (fun f -> f "Fid not bound, returning badfid");
      Error.badfid

  let remove connection ~cancel { Request.Remove.fid } =
    try
      let resource = Types.Fid.Map.find fid !(connection.fids) in
      match resource with
      | Entry _ | ControlFile _ ->
        clunk connection ~cancel { Request.Clunk.fid }
      | _ ->
        Log.err (fun f ->
            f "EPERM removing resource %s" (string_of_resource resource));
        Error.eperm
    with Not_found ->
      Log.err (fun f -> f "Fid not bound, returning badfid");
      Error.badfid

  let wstat _info ~cancel:_ _ = Error.eperm
end

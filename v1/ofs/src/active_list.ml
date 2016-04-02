
open Utils

let finally f g =
  let open Lwt.Infix in
  Lwt.catch (fun () -> f () >>= fun r -> g () >>= fun () -> Lwt.return r) (fun e -> g () >>= fun () -> Lwt.fail e)

module type Instance = sig
  type t
  val to_string: t -> string
  val of_string: string -> (t, [ `Msg of string ]) Result.result

  val description_of_format: string

  type context
  (** The context in which a [t] is [start]ed, for example a TCP/IP stack *)

  val start: context -> t -> (t, [ `Msg of string ]) Result.result Lwt.t

  val stop: t -> unit Lwt.t

  type key
  val get_key: t -> key
end

module Ivar = struct
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
    let open Lwt.Infix in
    let rec loop () = match t.thing with
      | Some c -> Lwt.return c
      | None ->
        Lwt_condition.wait t.c
        >>= fun () ->
        loop () in
    loop ()
end

module Transaction = struct
  type t = {
    name: string; (* directory name *)
    mutable source: string;
    mutable destination: string;
  }
end

module StringMap = Map.Make(String)

module Make(Instance: Instance) = struct
  open Protocol_9p

  type t = {
    context: Instance.context Ivar.t;
  }

  let make () =
    let context = Ivar.create () in
    { context }

  let set_context { context } x = Ivar.fill context x

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

  type connection = {
    t: t;
    fids: resource Types.Fid.Map.t ref;
  }

  let connect t info = {
    t;
    fids = ref (Types.Fid.Map.empty);
  }

  module Error = struct
    let badfid = Lwt.return (Response.error "fid not found")
    let badwalk = Lwt.return (Response.error "bad walk") (* TODO: ? *)

    let enoent = Lwt.return (Response.error "file not found")
    let eperm  = Lwt.return (Response.error "permission denied")
  end

  let qid_path = ref 0_L

  let next_qid flags =
    let id = !qid_path in
    qid_path := Int64.(add one !qid_path);
    Protocol_9p.Types.Qid.({ flags; version = 0_l; id; })

  let root_qid = next_qid [ Types.Qid.Directory ]

  let readme = Cstruct.of_string (Printf.sprintf "
Directory of active Instances
-----------------------------

Every active Instance is represented by a file. To shut down an Instance,
remove the file.

To request an additional Instance, make a directory with a unique name,
then open the special file `ctl` inside, and `write` a single string of the following
form:

%s

Immediately read the file contents and check whether it says:

- `OK <instance details>`: this means the Instance has been configured and
  the details returned to you. For some instance types the server might modify
  the request slightly, for example by choosing a local port number or
  temporary path.
- `ERROR some error message`: this means the Instance creation has failed, perhaps
  some needed resource is still in use.

The directory will be deleted and replaced with a file of the same name.
" Instance.description_of_format)

  let return x = Lwt.return (Result.Ok x)

  let attach connection ~cancel { Request.Attach.fid } =
    connection.fids := Types.Fid.Map.add fid Root !(connection.fids);
    return { Response.Attach.qid = root_qid }

  let walk connection ~cancel { Request.Walk.fid; newfid; wnames } =
    try
      let from = Types.Fid.Map.find fid !(connection.fids) in
      let from, wqids = List.fold_left (fun (from,qids) x -> match x, fst from with
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
            end else failwith "ENOENT"
          | "ctl", Entry entry ->
            let qid = next_qid [] in
            (ControlFile entry, qid), qid :: qids
          | _, _ -> failwith "ENOENT"
        ) ((from, next_qid []), []) wnames in
      connection.fids := Types.Fid.Map.add newfid (fst from) !(connection.fids);
      let wqids = List.rev wqids in
      return { Response.Walk.wqids }
    with
    | Not_found -> Error.badfid
    | Failure "ENOENT" -> Error.enoent
    | Failure "BADWALK" -> Error.badwalk

  let clunk connection ~cancel { Request.Clunk.fid } =
    connection.fids := Types.Fid.Map.remove fid !(connection.fids);
    return ()

  let open_ connection ~cancel { Request.Open.fid; mode } =
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

  let errors_to_client = Result.(function
      | Error (`Msg msg) -> Error { Response.Err.ename = msg; errno = None }
      | Ok _ as ok -> ok
    )

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
    | Result.Ok offset' ->
      let data = Cstruct.sub buf 0 (max 0 (offset' - offset)) in
      return { Response.Read.data }
    | Result.Error _ -> Error.badfid

  let dot = make_stat ~is_directory:true ~writable:false ~name:"."
  let dotdot = make_stat ~is_directory:true ~writable:false ~name:".."

  let read_string count offset message =
    let data = Cstruct.create (String.length message) in
    Cstruct.blit_from_string message 0 data 0 (String.length message);
    let len = min count Cstruct.(len data - offset) in
    let data = Cstruct.sub data offset len in
    return { Response.Read.data }

  let read connection ~cancel { Request.Read.fid; offset; count } =
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
      | Entry { instance = Some i } ->
        let i' = Instance.to_string i in
        read_string count offset (i' ^ "\n")
      | Entry { instance = None } ->
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

  let stat connection ~cancel { Request.Stat.fid } =
    try
      let resource = Types.Fid.Map.find fid !(connection.fids) in
      let stat = match resource with
        | Root -> make_stat ~is_directory:true ~writable:true ~name:""
        | README -> make_stat ~is_directory:false ~writable:false ~name:"README"
        | ControlFile _ -> make_stat ~is_directory:false ~writable:true ~name:"ctl"
        | Entry { name; instance = None } -> make_stat ~is_directory:true ~writable:false ~name
        | Entry { name; instance = Some _ } -> make_stat ~is_directory:false ~writable:false ~name in
      return { Response.Stat.stat }
    with Not_found -> Error.badfid

  let create connection ~cancel { Request.Create.fid; name; perm; mode } =
    let resource = Types.Fid.Map.find fid !(connection.fids) in
    match resource with
    | Root when perm.Types.FileMode.is_directory ->
      let qid = next_qid [ Types.Qid.Directory ] in
      active := StringMap.add name { name; instance = None; result = None } !active;
      return { Response.Create.qid; iounit = 512l }
    | _ ->
      Error.eperm

  let write connection ~cancel { Request.Write.fid; offset; data } =
    let ok = { Response.Write.count = Int32.of_int @@ Cstruct.len data } in
    try
      let resource = Types.Fid.Map.find fid !(connection.fids) in
      match resource with
      | ControlFile entry ->
        if entry.result <> None
        then Error.eperm
        else begin match Instance.of_string @@ Cstruct.to_string data with
        | Result.Ok f ->
          let open Lwt.Infix in
          Ivar.read connection.t.context
          >>= fun context ->
          begin Instance.start context f >>= function
            | Result.Ok f' -> (* local_port is resolved *)
              entry.instance <- Some f';
              entry.result <- Some ("OK " ^ (Instance.to_string f') ^ "\n");
              return ok
            | Result.Error (`Msg m) ->
              entry.result <- Some ("ERROR " ^ m ^ "\n");
              return ok
          end
        | Result.Error (`Msg m) ->
          entry.result <- Some ("ERROR " ^ m ^ "\n");
          return ok
        end
      | _ -> Error.eperm
    with Not_found -> Error.badfid

  let remove connection ~cancel { Request.Remove.fid } =
    try
      let resource = Types.Fid.Map.find fid !(connection.fids) in
      match resource with
      | Entry entry
      | ControlFile entry ->
        let open Lwt.Infix in
        ( match entry.instance with
          | None -> Lwt.return ()
          | Some f -> Instance.stop f )
        >>= fun () ->
        entry.instance <- None;
        active := StringMap.remove entry.name !active;
        clunk connection ~cancel { Request.Clunk.fid }
      | _ -> Error.eperm
    with Not_found -> Error.badfid

  let wstat _info ~cancel _ = Error.eperm
end

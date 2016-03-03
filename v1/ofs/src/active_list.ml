
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
  module Map: Map.S with type key = key
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

module Make(Instance: Instance) = struct
  open Protocol_9p

  let active : Instance.t Instance.Map.t ref = ref Instance.Map.empty

  type t = {
    context: Instance.context Ivar.t;
  }

  let make () =
    let context = Ivar.create () in
    { context }

  let set_context { context } x = Ivar.fill context x

  type resource =
    | ControlFile (* "/ctl" *)
    | README
    | Instance of Instance.t
    | Root

  type connection = {
    t: t;
    fids: resource Types.Fid.Map.t ref;
    mutable result: string option;
  }

  let connect t info = {
    t;
    fids = ref (Types.Fid.Map.empty);
    result = None;
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

  let root_qid = next_qid []

  let readme = Cstruct.of_string (Printf.sprintf "
Directory of active Instances
-----------------------------

Every active Instance is represented by a file. To shut down an Instance,
remove the file.

To request an additional Instance, open the special file `/ctl` and `write`
a single string of the following form:

%s

Immediately read the file contents and check whether it says:

- `OK <instance details>`: this means the Instance has been configured and
  the details returned to you. For some instance types the server might modify
  the request slightly, for example by choosing a local port number or
  temporary path.
- `ERROR some error message`: this means the Instance creation has failed, perhaps
  some needed resource is still in use.
" Instance.description_of_format)

  let return x = Lwt.return (Result.Ok x)

  let attach connection ~cancel { Request.Attach.fid } =
    connection.fids := Types.Fid.Map.add fid Root !(connection.fids);
    return { Response.Attach.qid = root_qid }

  let walk connection ~cancel { Request.Walk.fid; newfid; wnames } =
    try
      let from = Types.Fid.Map.find fid !(connection.fids) in
      let from, wqids = List.fold_left (fun (from,qids) -> function
          | ".." ->
            (Root, root_qid), root_qid::qids
          | "README" ->
            let qid = next_qid [] in
            (README, qid), qid :: qids
          | "ctl" ->
            let qid = next_qid [] in
            (ControlFile, qid), qid :: qids
          | instance ->
            begin match Instance.of_string instance with
              | Result.Error _ -> failwith "ENOENT"
              | Result.Ok f ->
                let key = Instance.get_key f in
                if Instance.Map.mem key !active then begin
                  let qid = next_qid [] in
                  (Instance (Instance.Map.find key !active), qid), qid :: qids
                end else failwith "ENOENT"
            end
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

  let read connection ~cancel { Request.Read.fid; offset; count } =
    let count = Int32.to_int count in
    let offset = Int64.to_int offset in
    try
      let resource = Types.Fid.Map.find fid !(connection.fids) in
      match resource with
      | ControlFile ->
        let message = match connection.result with
          | None -> "ERROR no request received. Please read the README.\n"
          | Some x -> x in
        let data = Cstruct.create (String.length message) in
        Cstruct.blit_from_string message 0 data 0 (String.length message);
        let len = min count Cstruct.(len data - offset) in
        let data = Cstruct.sub data offset len in
        if Cstruct.len data = 0 then connection.result <- None;
        return { Response.Read.data }
      | README ->
        let len = min count Cstruct.(len readme - offset) in
        let data = Cstruct.sub readme offset len in
        return { Response.Read.data }
      | Instance f ->
        let f' = Instance.to_string f in
        let data = Cstruct.create (String.length f') in
        Cstruct.blit_from_string f' 0 data 0 (Cstruct.len data);
        let len = min count Cstruct.(len data - offset) in
        let data = Cstruct.sub data offset len in
        return { Response.Read.data }
      | Root ->
        let children =
          make_stat ~is_directory:true ~writable:false ~name:"."
          :: make_stat ~is_directory:true ~writable:false ~name:".."
          :: make_stat ~is_directory:false ~writable:false ~name:"README"
          :: make_stat ~is_directory:false ~writable:false ~name:"ctl"
          :: (Instance.Map.fold (fun _ instance acc ->
              make_stat ~is_directory:false ~writable:false ~name:(Instance.to_string instance)
              :: acc) !active []) in
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
    with Not_found -> Error.badfid

  let stat connection ~cancel { Request.Stat.fid } =
    try
      let resource = Types.Fid.Map.find fid !(connection.fids) in
      let stat = match resource with
        | Root -> make_stat ~is_directory:true ~writable:true ~name:""
        | README -> make_stat ~is_directory:false ~writable:false ~name:"README"
        | ControlFile -> make_stat ~is_directory:false ~writable:true ~name:"ctl"
        | Instance f -> make_stat ~is_directory:false ~writable:false ~name:(Instance.to_string f) in
      return { Response.Stat.stat }
    with Not_found -> Error.badfid

  let create connection ~cancel _ = Error.eperm

  let write connection ~cancel { Request.Write.fid; offset; data } =
    let ok = { Response.Write.count = Int32.of_int @@ Cstruct.len data } in
    try
      let resource = Types.Fid.Map.find fid !(connection.fids) in
      match resource with
      | ControlFile ->
        if connection.result <> None
        then Error.eperm
        else begin match Instance.of_string @@ Cstruct.to_string data with
          | Result.Ok f ->
            let open Lwt.Infix in
            Ivar.read connection.t.context
            >>= fun context ->
            begin Instance.start context f >>= function
              | Result.Ok f' -> (* local_port is resolved *)
                let key = Instance.get_key f' in
                active := Instance.Map.add key f' !active;
                connection.result <- Some ("OK " ^ (Instance.to_string f') ^ "\n");
                return ok
              | Result.Error (`Msg m) ->
                connection.result <- Some ("ERROR " ^ m ^ "\n");
                return ok
            end
          | Result.Error (`Msg m) ->
            connection.result <- Some ("ERROR " ^ m ^ "\n");
            return ok
        end
      | _ -> Error.eperm
    with Not_found -> Error.badfid

  let remove connection ~cancel { Request.Remove.fid } =
    try
      let resource = Types.Fid.Map.find fid !(connection.fids) in
      match resource with
      | Instance f ->
        let open Lwt.Infix in
        Instance.stop f
        >>= fun () ->
        let key = Instance.get_key f in
        active := Instance.Map.remove key !active;
        clunk connection ~cancel { Request.Clunk.fid }
      | _ -> Error.eperm
    with Not_found -> Error.badfid

  let wstat _info ~cancel _ = Error.eperm
end

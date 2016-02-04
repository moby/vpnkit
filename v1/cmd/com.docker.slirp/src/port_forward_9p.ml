
open Utils

let src =
  let src = Logs.Src.create "port forward" ~doc:"forward local ports to the VM" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let finally f g =
  let open Lwt.Infix in
  Lwt.catch (fun () -> f () >>= fun r -> g () >>= fun () -> Lwt.return r) (fun e -> g () >>= fun () -> Lwt.fail e)

module type Instance = sig

  type t
  val to_string: t -> string
  val of_string: string -> (t, [ `Msg of string ]) Result.result

  type context = Tcpip_stack.t
  (** The context in which a [t] is [start]ed, for example a TCP/IP stack *)

  val start: context -> t -> (t, [ `Msg of string ]) Result.result Lwt.t

  val stop: t -> unit Lwt.t

  type key
  val get_key: t -> key
  module Map: Map.S with type key = key
end


module Fs(Forward: Instance) = struct
  open Protocol_9p

  let active : Forward.t Forward.Map.t ref = ref Forward.Map.empty

  type t = {
    mutable stack: Tcpip_stack.t option;
  }

  let make () = { stack = None }

  let set_stack t stack = t.stack <- Some stack

  type resource =
    | ControlFile (* "/ctl" *)
    | README
    | Forward of Forward.t
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

  let readme = Cstruct.of_string "
Active port fowards directory
-----------------------------

Every active port forward is represented by a file, whose name is the
local port number. The file contents are of the form:

<destination IP>:<destination port>

The files may not be written to, but may be read and removed. When a file
is removed, the listening socket is closed (but active connection forwards
remain active).

To request an additional forward of a specific local port, open the
special file `/ctl` and write `local_port:destination_ip:destination_port`.
Immediately read the file contents and check whether it says:

- `OK local_port:destination_ip:destination_port`: this means the forwarding
  has been setup on `127.0.0.1:local_port`.
- `ERROR some error message`: this means the forwarding has failed, perhaps
  the port is still in use.

To request an additional forward of any free local port, open the special
file `/ctl` and write `0:destination_ip:destination_port` then read the file
contents to discover the identity of the allocated local port, or details of
the failure.
"

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
          | forward ->
            begin match Forward.of_string forward with
              | Result.Error _ -> failwith "ENOENT"
              | Result.Ok f ->
                let key = Forward.get_key f in
                if Forward.Map.mem key !active then begin
                  let qid = next_qid [] in
                  (Forward (Forward.Map.find key !active), qid), qid :: qids
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
      | Forward f ->
        let f' = Forward.to_string f in
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
          :: (Forward.Map.fold (fun _ forward acc ->
              make_stat ~is_directory:false ~writable:false ~name:(Forward.to_string forward)
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
        | Forward f -> make_stat ~is_directory:false ~writable:false ~name:(Forward.to_string f) in
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
        else begin match Forward.of_string @@ Cstruct.to_string data with
          | Result.Ok f ->
            let open Lwt.Infix in
            begin match connection.t.stack with
              | None ->
                connection.result <- Some ("ERROR no TCP/IP stack configured\n");
                return ok
              | Some stack ->
                begin Forward.start stack f >>= function
                  | Result.Ok f' -> (* local_port is resolved *)
                    let key = Forward.get_key f' in
                    active := Forward.Map.add key f' !active;
                    connection.result <- Some ("OK " ^ (Forward.to_string f') ^ "\n");
                    return ok
                  | Result.Error (`Msg m) ->
                    connection.result <- Some ("ERROR " ^ m ^ "\n");
                    return ok
                end
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
      | Forward f ->
        let open Lwt.Infix in
        Forward.stop f
        >>= fun () ->
        let key = Forward.get_key f in
        active := Forward.Map.remove key !active;
        clunk connection ~cancel { Request.Clunk.fid }
      | _ -> Error.eperm
    with Not_found -> Error.badfid

  let wstat _info ~cancel _ = Error.eperm
end

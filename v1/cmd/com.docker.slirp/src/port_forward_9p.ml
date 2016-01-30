
let src =
  let src = Logs.Src.create "port forward" ~doc:"forward local ports to the VM" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let finally f g =
  let open Lwt.Infix in
  Lwt.catch (fun () -> f () >>= fun r -> g () >>= fun () -> Lwt.return r) (fun e -> g () >>= fun () -> Lwt.fail e)

module Result = struct
  include Result
  let return x = Ok x
  let errorf fmt = Printf.ksprintf (fun s -> Error (`Msg s)) fmt
end

module Port = struct
  module M = struct
    type t = int
    let compare (a: t) (b: t) = Pervasives.compare a b
  end
  include M
  module Map = Map.Make(M)
  module Set = Set.Make(M)
  let of_string x =
    try
      let x = int_of_string x in
      if x < 0 || x > 65535
      then Result.errorf "port out of range: 0 <= %d <= 65536" x
      else Result.return x
    with
    | _ -> Result.errorf "port is not an integer: '%s'" x
end

module Forward = struct
  type t = {
    local_port: Port.t;
    remote_ip: Ipaddr.V4.t;
    remote_port: Port.t;
    mutable fd: Lwt_unix.file_descr option;
  }
  let to_string t = Printf.sprintf "%d:%s:%d" t.local_port (Ipaddr.V4.to_string t.remote_ip) t.remote_port
  let start stack t =
    let addr = Lwt_unix.ADDR_INET(Unix.inet_addr_of_string "127.0.0.1", t.local_port) in
    let fd = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_STREAM 0 in
    Lwt_unix.setsockopt fd Lwt_unix.SO_REUSEADDR true;
    let open Lwt.Infix in
    Lwt.catch
      (fun () ->
        Lwt_unix.bind fd addr;
        match Lwt_unix.getsockname fd with
        | Lwt_unix.ADDR_INET(_, local_port) ->
          let t = { t with local_port; fd = Some fd } in
          let description = to_string t in
          Lwt_unix.listen fd 5;
          let rec loop () =
            Lwt_unix.accept fd
            >>= fun (local_fd, _) ->
            let local = Socket.TCPV4.of_fd ~description local_fd in
            let proxy () =
              finally (fun () ->
                Tcpip_stack.TCPV4.create_connection (Tcpip_stack.tcpv4 stack) (t.remote_ip,t.remote_port)
                >>= function
                | `Error e ->
                  Log.err (fun f -> f "%s: failed to connect: %s" description (Tcpip_stack.TCPV4.error_message e));
                  Lwt.return ()
                | `Ok remote ->
                  (* The proxy function will close the remote flow *)
                  (* proxy between local and remote *)
                  Log.info (fun f -> f "%s connected" description);
                  Mirage_flow.proxy (module Clock) (module Tcpip_stack.TCPV4_half_close) remote (module Socket.TCPV4) local ()
                  >>= function
                  | `Error (`Msg m) ->
                    Log.err (fun f -> f "%s proxy failed with %s" description m);
                    Lwt.return ()
                  | `Ok (l_stats, r_stats) ->
                    Log.info (fun f ->
                        f "%s closing: l2r = %s; r2l = %s" description
                          (Mirage_flow.CopyStats.to_string l_stats) (Mirage_flow.CopyStats.to_string r_stats)
                      );
                    Lwt.return ()
              ) (fun () ->
                Socket.TCPV4.close local
                >>= fun () ->
                Log.info (fun f -> f "%s close local" description);
                Lwt.return ()
              ) in
            Lwt.async proxy;
            loop () in
          Lwt.async loop;
          Lwt.return (Result.Ok t)
        | _ ->
          Lwt.fail (Failure "failed to query local port")
      ) (function
        | Failure m ->
          Lwt_unix.close fd
          >>= fun () ->
          Lwt.return (Result.Error (`Msg m))
        | e ->
          Lwt_unix.close fd
          >>= fun () ->
          Lwt.return (Result.Error (`Msg (Printf.sprintf "failed to bind port %s" (Printexc.to_string e))))
      )

  let stop t = match t.fd with
    | None -> Lwt.return ()
    | Some fd ->
      t.fd <- None;
      Lwt_unix.close fd
  let of_string x = match Stringext.split ~on:':' x with
    | [ local_port; remote_ip; remote_port ] ->
      let local_port = Port.of_string local_port in
      let remote_ip = Ipaddr.V4.of_string remote_ip in
      let remote_port = Port.of_string remote_port in
      begin match local_port, remote_ip, remote_port with
        | Result.Ok local_port, Some remote_ip, Result.Ok remote_port ->
          Result.Ok { local_port; remote_ip; remote_port; fd = None }
        | Result.Error (`Msg m), _, _ ->
          Result.Error (`Msg ("Failed to parse local port: " ^ m))
        | _, None, _ ->
          Result.Error (`Msg "Failed to parse remote IPv4 address")
        | _, _, Result.Error (`Msg m) ->
          Result.Error (`Msg ("Failed to parse remote port: " ^ m))
      end
    | _ ->
      Result.Error (`Msg ("Failed to parse request, expected local_port:remote_ip:remote_port"))
end

let active : Forward.t Port.Map.t ref = ref Port.Map.empty

module Fs = struct
  open Protocol_9p

  type t = {
    stack: Tcpip_stack.t;
  }

  let make stack = { stack }

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
                if Port.Map.mem f.Forward.local_port !active then begin
                  let qid = next_qid [] in
                  (Forward (Port.Map.find f.Forward.local_port !active), qid), qid :: qids
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
          :: (Port.Map.fold (fun _ forward acc ->
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
            begin Forward.start connection.t.stack f >>= function
            | Result.Ok f' -> (* local_port is resolved *)
              active := Port.Map.add f'.Forward.local_port f' !active;
              connection.result <- Some ("OK " ^ (Forward.to_string f') ^ "\n");
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
      | Forward f ->
        let open Lwt.Infix in
        Forward.stop f
        >>= fun () ->
        active := Port.Map.remove f.Forward.local_port !active;
        clunk connection ~cancel { Request.Clunk.fid }
      | _ -> Error.eperm
    with Not_found -> Error.badfid

  let wstat _info ~cancel _ = Error.eperm
end

module Server = Server9p_unix.Make(Log9p_unix.Stdout)(Fs)

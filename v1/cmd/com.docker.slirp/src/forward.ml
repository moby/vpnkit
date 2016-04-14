open Utils

let src =
  let src = Logs.Src.create "port forward" ~doc:"forward local ports to the VM" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let finally f g =
  let open Lwt.Infix in
  Lwt.catch (fun () -> f () >>= fun r -> g () >>= fun () -> Lwt.return r) (fun e -> g () >>= fun () -> Lwt.fail e)

let allowed_addresses = ref None

let set_allowed_addresses ips =
  Log.info (fun f -> f "allowing binds to %s" (match ips with
    | None -> "any IP addresses"
    | Some ips -> String.concat ", " (List.map Ipaddr.to_string ips)
  ));
  allowed_addresses := ips

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

module VsockPort = struct
  type t = int32

  let of_string x =
    try
      Result.return @@ Int32.of_string ("0x" ^ x)
    with
    | _ -> Result.errorf "vchan port is not a hexadecimal int32: '%s'" x
end

module Local = struct
  module M = struct
    type t = [
      | `Ip of Ipaddr.V4.t * Port.t
      | `Unix of string
    ]
    let compare = compare
  end
  include M
  module Map = Map.Make(M)
  module Set = Set.Make(M)

  let to_string = function
    | `Ip (addr, port) -> Printf.sprintf "%s:%d" (Ipaddr.V4.to_string addr) port
    | `Unix path -> "unix:" ^ path
end

type t = {
  local: Local.t;
  remote_port: VsockPort.t; (* vsock port *)
  mutable fd: Lwt_unix.file_descr option;
  mutable path: string option;
}

type key = Local.t

let get_key t = t.local

module Map = Local.Map

type context = string

let to_string t = Printf.sprintf "%s:%08lx" (Local.to_string t.local) t.remote_port

let description_of_format = "'[local ip:]local port:remote vchan port' or 'unix:local path:remote vchan port' where the remote vchan port matches %08x"

let rm_f path =
  Lwt.catch
    (fun () -> Lwt_unix.unlink path)
    (function
      | Unix.Unix_error(Unix.ENOENT, _, _) -> Lwt.return ()
      | e ->
        Log.err (fun f -> f "failed to remove %s: %s" path (Printexc.to_string e));
        Lwt.return ()
    )

let finally f g =
  let open Lwt.Infix in
  Lwt.catch (fun () ->
    f ()
    >>= fun r ->
    g ()
    >>= fun () ->
    Lwt.return r
  ) (fun e ->
    g ()
    >>= fun () ->
    Lwt.fail e
  )

let check_bind_allowed ip = match !allowed_addresses with
  | None -> Lwt.return () (* no restriction *)
  | Some ips ->
    let match_ipv4 = function
      | Ipaddr.V6 _ -> false
      | Ipaddr.V4 x when x = Ipaddr.V4.any -> true
      | Ipaddr.V4 x -> x = ip in
    if List.fold_left (||) false (List.map match_ipv4 ips)
    then Lwt.return ()
    else Lwt.fail (Unix.Unix_error(Unix.EPERM, "bind", ""))

let bind local =
  let open Lwt.Infix in
  match local with
  | `Unix path ->
    rm_f path
    >>= fun () ->
    let fd = Lwt_unix.socket Lwt_unix.PF_UNIX Lwt_unix.SOCK_STREAM 0 in
    Lwt.catch
      (fun () -> Lwt_unix.bind fd (Lwt_unix.ADDR_UNIX(path)); Lwt.return ())
      (fun e -> Lwt_unix.close fd >>= fun () -> Lwt.fail e)
    >>= fun () ->
    Lwt.return (Result.Ok fd)
  | `Ip (local_ip, local_port) when local_port < 1024 ->
    check_bind_allowed local_ip
    >>= fun () ->
    let s = Lwt_unix.socket Lwt_unix.PF_UNIX Lwt_unix.SOCK_STREAM 0 in
    finally
      (fun () ->
        let open Lwt.Infix in
        Lwt_unix.connect s (Unix.ADDR_UNIX "/var/tmp/com.docker.vmnetd.socket")
        >>= fun () ->
        Vmnet.Client.of_fd s
        >>= fun r ->
        begin match r with
        | `Error (`Msg x) -> Lwt.return (Result.Error (`Msg x))
        | `Ok c ->
          Vmnet.Client.bind_ipv4 c (local_ip, local_port)
          >>= fun r ->
          begin match r with
          | `Ok fd ->
            Log.debug (fun f -> f "Received fd successfully");
            Lwt.return (Result.Ok fd)
          | `Error (`Msg x) ->
            Log.err (fun f -> f "Error binding to %s:%d: %s" (Ipaddr.V4.to_string local_ip) local_port x);
            Lwt.return (Result.Error (`Msg x))
          end
        end
      ) (fun () -> Lwt_unix.close s)
  | `Ip (local_ip, local_port) ->
    check_bind_allowed local_ip
    >>= fun () ->
    let addr = Lwt_unix.ADDR_INET(Unix.inet_addr_of_string (Ipaddr.V4.to_string local_ip), local_port) in
    let fd = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_STREAM 0 in
    Lwt.catch
      (fun () -> Lwt_unix.bind fd addr; Lwt.return ())
      (fun e -> Lwt_unix.close fd >>= fun () -> Lwt.fail e)
    >>= fun () ->
    Lwt.return (Result.Ok fd)

let start vsock_path_var t =
  let open Lwt.Infix in
  let path = match t.local with `Unix path -> Some path | _ -> None in
  bind t.local
  >>= function
  | Result.Error e -> Lwt.return (Result.Error e)
  | Result.Ok fd ->
  Lwt_unix.setsockopt fd Lwt_unix.SO_REUSEADDR true;
  (* On failure here, we must close the fd *)
  Lwt.catch
    (fun () ->
       Lwt_unix.listen fd 5;
       match t.local, Lwt_unix.getsockname fd with
       | `Ip (local_ip, _), Lwt_unix.ADDR_INET(_, local_port) ->
         let t = { t with local = `Ip(local_ip, local_port) } in
         Lwt.return (Result.Ok (t, fd, path))
       | `Unix _, Lwt_unix.ADDR_UNIX(_) ->
         Lwt.return (Result.Ok (t, fd, path))
       | _ ->
         Lwt.return (Result.Error (`Msg "failed to query local port"))
    ) (fun e ->
        Lwt_unix.close fd
        >>= fun () ->
        (* Pretty-print the most common exception *)
        let message = match e with
        | Unix.Unix_error(Unix.EADDRINUSE, _, _) -> "address already in use"
        | e -> Printexc.to_string e in
        Lwt.return (Result.Error (`Msg (Printf.sprintf "failed to bind port: %s" message)))
      )
  >>= function
  | Result.Error e -> Lwt.return (Result.Error e)
  | Result.Ok (t, fd, path) ->
    (* The `Forward.stop` function is in charge of closing the fd *)
    let t = { t with fd = Some fd; path } in
    let description = to_string t in
    let rec loop () =
      Lwt.catch (fun () ->
          Lwt_unix.accept fd
          >>= fun (local_fd, _) ->
          Lwt.return (Some local_fd)
        ) (function
          | Unix.Unix_error(Unix.EBADF, _, _) -> Lwt.return None
          | e ->
            Log.err (fun f -> f "%s: failed to accept: %s" description (Printexc.to_string e));
            Lwt.return None
        )
      >>= function
      | None ->
        Log.debug (fun f -> f "%s: listening thread shutting down" description);
        Lwt.return ()
      | Some local_fd ->
        let local = Socket.Stream.of_fd ~description local_fd in
        Active_list.Var.read vsock_path_var
        >>= fun vsock_path ->
        let proxy () =
          finally (fun () ->
            Osx_hyperkit.Vsock.connect ~path:vsock_path ~port:t.remote_port ()
            >>= fun v ->
            let remote = Socket.Stream.of_fd ~description v in
            finally (fun () ->
              (* proxy between local and remote *)
              Log.debug (fun f -> f "%s: connected" description);
              Mirage_flow.proxy (module Clock) (module Socket.Stream) remote (module Socket.Stream) local ()
              >>= function
              | `Error (`Msg m) ->
                Log.err (fun f -> f "%s proxy failed with %s" description m);
                Lwt.return ()
              | `Ok (l_stats, r_stats) ->
                Log.debug (fun f ->
                    f "%s completed: l2r = %s; r2l = %s" description
                      (Mirage_flow.CopyStats.to_string l_stats) (Mirage_flow.CopyStats.to_string r_stats)
                  );
                Lwt.return ()
            ) (fun () ->
              Socket.Stream.close remote
            )
          ) (fun () ->
            Socket.Stream.close local
            >>= fun () ->
            Lwt.return ()
          )
        in
        Lwt.async (fun () -> log_exception_continue (description ^ " proxy") proxy);
        loop () in
    Lwt.async loop;
    Lwt.return (Result.Ok t)

let stop t = match t.fd with
  | None -> Lwt.return ()
  | Some fd ->
    let open Lwt.Infix in
    t.fd <- None;
    Log.debug (fun f -> f "%s: closing listening socket" (to_string t));
    Lwt_unix.close fd
    >>= fun () ->
    match t.path with
    | None -> Lwt.return ()
    | Some path ->
      t.path <- None;
      rm_f path

let of_string x =
  match (
    match Stringext.split ~on:':' x with
    | [ "unix"; path; remote_port ] ->
      Result.Ok (
        `Unix path,
        VsockPort.of_string remote_port
      )
    | [ local_ip; local_port; remote_port ] ->
      let local_ip = Ipaddr.V4.of_string local_ip in
      let local_port = Port.of_string local_port in
      begin match local_ip, local_port with
      | Some ip, Result.Ok port ->
        Result.Ok (
          `Ip (ip, port),
          VsockPort.of_string remote_port
        )
      | _, _ -> Result.Error (`Msg ("Failed to parse local IP and port: " ^ x))
      end
    | [ local_port; remote_port ] ->
      begin match Port.of_string local_port with
      | Result.Error x -> Result.Error x
      | Result.Ok port ->
        Result.Ok (
          `Ip(Ipaddr.V4.of_string_exn "127.0.0.1", port),
          VsockPort.of_string remote_port
        )
      end
    | _ ->
      Result.Error (`Msg ("Failed to parse request, expected " ^ description_of_format))
  ) with
  | Result.Error x -> Result.Error x
  | Result.Ok (local, Result.Ok remote_port) ->
    Result.Ok { local; remote_port; fd = None; path = None }
  | Result.Ok (_, Result.Error (`Msg m)) ->
    Result.Error (`Msg ("Failed to parse remote port: " ^ m))

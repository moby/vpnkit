open Lwt
open Hostnet

let src =
  let src = Logs.Src.create "usernet" ~doc:"Mirage TCP/IP <-> socket proxy" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let log_exception_continue description f =
  Lwt.catch
    (fun () -> f ())
    (fun e ->
       Log.err (fun f -> f "%s: caught %s" description (Printexc.to_string e));
       Lwt.return ()
    )

let or_failwith = function
  | Result.Error (`Msg m) -> failwith m
  | Result.Ok x -> x

module Forward = Forward.Make(Connect)(Bind)

let start_port_forwarding port_control_path vsock_path =
  Log.info (fun f -> f "starting port_forwarding port_control_path:%s vsock_path:%s" port_control_path vsock_path);
  (* Start the 9P port forwarding server *)
  Connect.vsock_path := vsock_path;
  let module Ports = Active_list.Make(Forward) in
  let module Server = Server9p_unix.Make(Log)(Ports) in
  let fs = Ports.make () in
  Socket_stack.connect ()
  >>= function
  | `Error (`Msg m) ->
    Log.err (fun f -> f "Failed to create a socket stack: %s" m);
    exit 1
  | `Ok _ ->
  Ports.set_context fs vsock_path;
  Osx_socket.listen port_control_path
  >>= fun port_s ->
  let server = Server.of_fd fs port_s in
  Server.serve_forever server
  >>= fun r ->
  Lwt.return (or_failwith r)

module Slirp_stack = Slirp.Make(Vmnet.Make(Hostnet.Conn_lwt_unix))(Resolv_conf)

let set_nofile nofile =
  let open Sys_resource.Resource in
  let soft = Limit.Limit nofile in
  let (_, hard) = Sys_resource_unix.getrlimit NOFILE in
  Log.info (fun f -> f "Setting soft fd limit to %d" nofile);
  try Sys_resource_unix.setrlimit NOFILE ~soft ~hard with
  | Errno.Error ex -> Log.warn (fun f -> f "setrlimit failed: %s" (Errno.string_of_error ex))

let main_t socket_path port_control_path vsock_path db_path nofile debug =
  Osx_reporter.install ~stdout:debug;
  Log.info (fun f -> f "Setting handler to ignore all SIGPIPE signals");
  Sys.set_signal Sys.sigpipe Sys.Signal_ignore;
  set_nofile nofile;
  Printexc.record_backtrace true;

  Lwt.async_exception_hook := (fun exn ->
    Log.err (fun f -> f "Lwt.async failure %s: %s"
      (Printexc.to_string exn)
      (Printexc.get_backtrace ())
    )
  );
  Osx_socket.listen socket_path
  >>= fun s ->

  Lwt.async (fun () ->
    log_exception_continue "start_port_server"
      (fun () ->
        start_port_forwarding port_control_path vsock_path
      )
    );

  let config = Active_config.create "unix" db_path in
  Slirp_stack.create config
  >>= fun stack ->
  let rec loop () =
    Lwt_unix.accept s
    >>= fun (client, _) ->
    Lwt.async (fun () ->
      log_exception_continue "slirp_server"
        (fun () ->
          let conn = Hostnet.Conn_lwt_unix.connect client in
          Slirp_stack.connect stack conn
        )
      (* NB: the vmnet layer will call close when it receives EOF *)
    );
    loop () in
  loop ()

let main socket port_control vsock_path db nofile debug = Lwt_main.run @@ main_t socket port_control vsock_path db nofile debug

open Cmdliner

(* NOTE(aduermael): it seems to me that "/var/tmp/com.docker.slirp.socket" is a default value, right?
This socket path is now dynamic, depending on current user's home directory. Could we just
make it fail instead? In case no argument is supplied? *)
let socket =
  Arg.(value & opt string "/var/tmp/com.docker.slirp.socket" & info [ "socket" ] ~docv:"SOCKET")

(* NOTE(aduermael): it seems to me that "/var/tmp/com.docker.port.socket" is a default value, right?
This socket path is now dynamic, depending on current user's home directory. Could we just
make it fail instead? In case no argument is supplied? *)
let port_control_path =
  Arg.(value & opt string "/var/tmp/com.docker.port.socket" & info [ "port-control" ] ~docv:"PORT")

(* NOTE(aduermael): it seems to me that "/var/tmp/com.docker.vsock/connect" is a default value, right?
This socket path is now dynamic, depending on current user's home directory. Could we just
make it fail instead? In case no argument is supplied? *)
let vsock_path =
  Arg.(value & opt string "/var/tmp/com.docker.vsock/connect" & info [ "vsock-path" ] ~docv:"VSOCK")

(* NOTE(aduermael): it seems to me that "/var/tmp/com.docker.db.socket" is a default value, right?
This socket path is now dynamic, depending on current user's home directory. Could we just
make it fail instead? In case no argument is supplied? *)
let db_path =
  Arg.(value & opt string "/var/tmp/com.docker.db.socket" & info [ "db" ] ~docv:"DB")

let nofile = Arg.(value & opt int 10240 & info [ "nofile" ] ~docv:"nofile rlimit")

let debug =
  let doc = "Verbose debug logging to stdout" in
  Arg.(value & flag & info [ "debug" ] ~doc)

let command =
  let doc = "proxy TCP/IP connections from an ethernet link via sockets" in
  let man =
    [`S "DESCRIPTION";
     `P "Terminates TCP/IP and UDP/IP connections from a client and proxy the\
         flows via userspace sockets"]
  in
  Term.(pure main $ socket $ port_control_path $ vsock_path $ db_path $ nofile $ debug),
  Term.info "proxy" ~doc ~man

let () =
  Printexc.record_backtrace true;
  match Term.eval command with
  | `Error _ -> exit 1
  | _ -> exit 0

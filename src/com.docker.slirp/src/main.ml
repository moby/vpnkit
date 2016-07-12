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

module Main(Host: Sig.HOST) = struct

module Connect = Connect.Make(Host.Sockets)
module Bind = Bind.Make(Host.Sockets)
module Resolv_conf = Resolv_conf.Make(Host.Files)
module Config = Active_config.Make(Host.Time)(Host.Sockets.Stream.Unix)

let unix_listen path =
  let startswith prefix x =
    let prefix' = String.length prefix in
    let x' = String.length x in
    prefix' <= x' && (String.sub x 0 prefix' = prefix) in
  if startswith "fd:" path then begin
    let i = String.sub path 3 (String.length path - 3) in
    (  try Lwt.return (int_of_string i)
       with _ -> Lwt.fail (Failure (Printf.sprintf "Failed to parse command-line argument [%s]" path))
    ) >>= fun x ->
    let fd = Unix_representations.file_descr_of_int x in
    Lwt.return (Host.Sockets.Stream.Unix.of_bound_fd fd)
  end else Host.Sockets.Stream.Unix.bind path

module Forward = Forward.Make(Connect)(Bind)

let start_port_forwarding port_control_path vsock_path =
  Log.info (fun f -> f "starting port_forwarding port_control_path:%s vsock_path:%s" port_control_path vsock_path);
  (* Start the 9P port forwarding server *)
  Connect.vsock_path := vsock_path;
  let module Ports = Active_list.Make(Forward) in
  let module Server = Protocol_9p.Server.Make(Log)(Host.Sockets.Stream.Unix)(Ports) in
  let fs = Ports.make () in
  Ports.set_context fs vsock_path;
  unix_listen port_control_path
  >>= fun port_s ->
  Host.Sockets.Stream.Unix.listen port_s
    (fun conn ->
      Server.connect fs conn ()
      >>= function
      | Result.Error (`Msg m) ->
        Log.err (fun f -> f "failed to establish 9P connection: %s" m);
        Lwt.return ()
      | Result.Ok server ->
        Server.after_disconnect server
  );
  Lwt.return ()

module Slirp_stack = Slirp.Make(Config)(Vmnet.Make(Host.Sockets.Stream.Unix))(Resolv_conf)(Host)

let set_nofile nofile =
  let open Sys_resource.Resource in
  let soft = Limit.Limit nofile in
  let (_, hard) = Sys_resource_unix.getrlimit NOFILE in
  Log.info (fun f -> f "Setting soft fd limit to %d" nofile);
  try Sys_resource_unix.setrlimit NOFILE ~soft ~hard with
  | Errno.Error ex -> Log.warn (fun f -> f "setrlimit failed: %s" (Errno.string_of_error ex))

let main_t socket_path port_control_path vsock_path db_path nofile pcap debug =
  (* Write to stdout if expicitly requested [debug = true] or if the environment
     variable DEBUG is set *)
  let env_debug = try ignore @@ Unix.getenv "DEBUG"; true with Not_found -> false in
  if debug || env_debug then begin
    Logs.set_reporter (Logs_fmt.reporter ());
    Log.info (fun f -> f "Logging to stdout (stdout:%b DEBUG:%b)" debug env_debug);
  end else begin
    let facility = Filename.basename Sys.executable_name in
    let client = Asl.Client.create ~ident:"Docker" ~facility () in
    Logs.set_reporter (Log_asl.reporter ~client ());
    let dev_null = Unix.openfile "/dev/null" [ Unix.O_WRONLY ] 0 in
    Unix.dup2 dev_null Unix.stdout;
    Unix.dup2 dev_null Unix.stderr;
    Log.info (fun f -> f "Logging to Apple System Log")
  end;
  Log.info (fun f -> f "Setting handler to ignore all SIGPIPE signals");
  Sys.set_signal Sys.sigpipe Sys.Signal_ignore;
  set_nofile nofile;
  Log.info (fun f -> f "vpnkit version %%VERSION%% with hostnet version %s %s and uwt version %s"
    Depends.hostnet_version Depends.hostnet_pinned Depends.uwt_version
  );
  Printexc.record_backtrace true;

  Lwt.async_exception_hook := (fun exn ->
    Log.err (fun f -> f "Lwt.async failure %s: %s"
      (Printexc.to_string exn)
      (Printexc.get_backtrace ())
    )
  );

  Lwt.async (fun () ->
    log_exception_continue "start_port_server"
      (fun () ->
        start_port_forwarding port_control_path vsock_path
      )
    );

  ( match db_path with
    | Some db_path ->
      let reconnect () =
        Host.Sockets.Stream.Unix.connect db_path
        >>= function
        | `Error (`Msg x) -> Lwt.return (Result.Error (`Msg x))
        | `Ok x -> Lwt.return (Result.Ok x) in
      let config = Config.create ~reconnect () in
      Slirp_stack.create config
    | None ->
      Log.warn (fun f -> f "no database: using hardcoded network configuration values");
      let never, _ = Lwt.task () in
      let pcap = match pcap with None -> None | Some filename -> Some (filename, None) in
      Lwt.return { Slirp_stack.peer_ip = Ipaddr.V4.of_string_exn "192.168.65.2";
        local_ip = Ipaddr.V4.of_string_exn "192.168.65.1";
        extra_dns_ip = Ipaddr.V4.of_string_exn "192.168.65.3";
        pcap_settings = Active_config.Value(pcap, never) }
  ) >>= fun stack ->

  unix_listen socket_path
  >>= fun server ->
  Host.Sockets.Stream.Unix.listen server
    (fun conn ->
      Slirp_stack.connect stack conn
      >>= fun stack ->
      Log.info (fun f -> f "stack connected");
      Slirp_stack.after_disconnect stack
      >>= fun () ->
      Log.info (fun f -> f "stack disconnected");
      Lwt.return ()
    );
  let wait_forever, _ = Lwt.task () in
  wait_forever

let main socket port_control vsock_path db nofile pcap debug =
  Host.Main.run @@ main_t socket port_control vsock_path db nofile pcap debug

end

let main socket port_control vsock_path db nofile pcap select debug =
  let module Use_lwt_unix = Main(Host_lwt_unix) in
  let module Use_uwt = Main(Host_uwt) in
  (if select then Use_lwt_unix.main else Use_uwt.main)
    socket port_control vsock_path db nofile pcap debug

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

let db_path =
  Arg.(value & opt (some string) None & info [ "db" ] ~docv:"DB")

let nofile = Arg.(value & opt int 10240 & info [ "nofile" ] ~docv:"nofile rlimit")

let pcap=
  let doc =
    Arg.info ~doc:
      "Filename to write packet capture data to" ["pcap"]
  in
  Arg.(value & opt (some string) None doc)

let select =
  let doc = "Use a select event loop rather than the default libuv-based one" in
  Arg.(value & flag & info [ "select" ] ~doc)

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
  Term.(pure main $ socket $ port_control_path $ vsock_path $ db_path $ nofile $ pcap $ select $ debug),
  Term.info (Filename.basename Sys.argv.(0)) ~version:"%%VERSION%%" ~doc ~man

let () =
  Printexc.record_backtrace true;
  match Term.eval command with
  | `Error _ -> exit 1
  | _ -> exit 0

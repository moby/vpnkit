open Lwt

let src =
  let src = Logs.Src.create "9P" ~doc:"/port filesystem" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log9P = (val Logs.src_log src : Logs.LOG)

let src =
  let src = Logs.Src.create "usernet" ~doc:"Mirage TCP/IP <-> socket proxy" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let _ =
  Printexc.register_printer (function
    | Unix.Unix_error(e, _, _) -> Some (Unix.error_message e)
    | _ -> None
    )

let log_exception_continue description f =
  Lwt.catch
    (fun () -> f ())
    (fun e ->
       Log.err (fun f -> f "%s: failed with %a" description Fmt.exn e);
       Lwt.return ()
    )

let ethernet_serviceid = "30D48B34-7D27-4B0B-AAAF-BBBED334DD59"
let ports_serviceid = "0B95756A-9985-48AD-9470-78E060895BE7"

let hvsock_addr_of_uri ~default_serviceid uri =
  (* hyperv://vmid/serviceid *)
  let vmid = match Uri.host uri with
  | None   -> Hvsock.Loopback
  | Some x -> Hvsock.Id x
  in
  let serviceid =
    let p = Uri.path uri in
    if p = ""
    then default_serviceid
    (* trim leading / *)
    else if String.length p > 0 then String.sub p 1 (String.length p - 1) else p
  in
  { Hvsock.vmid; serviceid }

  module Vnet = Basic_backend.Make
  module Connect_unix = Connect.Unix
  module Connect_hvsock = Connect.Hvsock
  module Bind = Bind.Make(Host.Sockets)
  module Dns_policy = Hostnet_dns.Policy(Host.Files)
  module Config = Active_config.Make(Host.Time)(Host.Sockets.Stream.Unix)
  module Forward_unix = Forward.Make(Mclock)(Connect_unix)(Bind)
  module Forward_hvsock = Forward.Make(Mclock)(Connect_hvsock)(Bind)
  module HV = Flow_lwt_hvsock.Make(Host.Time)(Host.Fn)
  module HostsFile = Hosts.Make(Host.Files)

  let file_descr_of_int (x: int) : Unix.file_descr =
    if Sys.os_type <> "Unix"
    then
      failwith "Cannot convert from an int to Unix.file_descr on platforms \
                other than Unix";
    Obj.magic x

  let unix_listen path =
    let startswith prefix x =
      let prefix' = String.length prefix in
      let x' = String.length x in
      prefix' <= x' && (String.sub x 0 prefix' = prefix) in
    if startswith "fd:" path then begin
      let i = String.sub path 3 (String.length path - 3) in
      (try Lwt.return (int_of_string i) with
      | _ ->
        Fmt.kstrf Lwt.fail_with "Failed to parse command-line argument [%s]" path
      ) >|= fun x ->
      let fd = file_descr_of_int x in
      Host.Sockets.Stream.Unix.of_bound_fd fd
    end else
      Host.Sockets.Stream.Unix.bind path

  let hvsock_connect_forever url sockaddr callback =
    Log.info (fun f ->
        f "connecting to %s:%s" (Hvsock.string_of_vmid sockaddr.Hvsock.vmid)
          sockaddr.Hvsock.serviceid);
    let rec aux () =
      let rec create () =
        match HV.Hvsock.create () with
        | x -> Lwt.return x
        | exception e ->
          Log.err (fun f -> f "caught %s while creating Hyper-V socket" (Printexc.to_string e));
          Host.Time.sleep_ns (Duration.of_sec 1)
          >>= fun () ->
          create () in
      create ()
      >>= fun socket ->
      Lwt.catch (fun () ->
          HV.Hvsock.connect ~timeout_ms:300 socket sockaddr >>= fun () ->
          Log.info (fun f -> f "hvsock connected successfully");
          callback socket
        ) (function
        | Unix.Unix_error(Unix.ETIMEDOUT, _, _) ->
          log_exception_continue "HV.Hvsock.close" (fun () -> HV.Hvsock.close socket)
          (* no need to add more delay *)
        | Unix.Unix_error(_, _, _) ->
          log_exception_continue "HV.Hvsock.close" (fun () -> HV.Hvsock.close socket)
          >>= fun () ->
          Host.Time.sleep_ns (Duration.of_sec 1)
        | _ ->
          log_exception_continue "HV.Hvsock.close" (fun () -> HV.Hvsock.close socket)
          >>= fun () ->
          Host.Time.sleep_ns (Duration.of_sec 1)
        )
      >>= fun () ->
      aux ()
    in
    Log.debug (fun f -> f "Waiting for connections on socket %s" url);
    Lwt.catch
      aux
      (fun e ->
        Log.err (fun f -> f "Caught %s while accepting connections on socket %s" (Printexc.to_string e) url);
        Lwt.return_unit
      )

  let start_introspection introspection_url root =
    if introspection_url = ""
    then Log.info (fun f ->
        f "no introspection server requested. See the --introspection argument")
    else Lwt.async (fun () ->
        log_exception_continue
          ("starting introspection server on: " ^ introspection_url)
          (fun () ->
             Log.info (fun f ->
                 f "starting introspection server on: %s" introspection_url);
             let module Server = Fs9p.Make(Host.Sockets.Stream.Unix) in
             unix_listen introspection_url >>= fun s ->
             Host.Sockets.Stream.Unix.disable_connection_tracking s;
             Host.Sockets.Stream.Unix.listen s (fun flow ->
                 Server.accept ~root ~msg:introspection_url flow >>= function
                 | Error (`Msg m) ->
                   Log.err (fun f ->
                       f "failed to establish 9P connection: %s" m);
                   Lwt.return ()
                 | Ok () ->
                   Lwt.return_unit
               );
             Lwt.return_unit))

  let start_diagnostics diagnostics_url flow_cb =
    if diagnostics_url = ""
    then Log.info (fun f ->
        f "no diagnostics server requested. See the --diagnostics argument")
    else Lwt.async (fun () ->
        log_exception_continue
          ("starting diagnostics server on: " ^ diagnostics_url)
          (fun () ->
             Log.info (fun f ->
                 f "starting diagnostics server on: %s" diagnostics_url);
             unix_listen diagnostics_url >|= fun s ->
             Host.Sockets.Stream.Unix.disable_connection_tracking s;
             Host.Sockets.Stream.Unix.listen s flow_cb))

  let start_port_forwarding port_control_url max_connections vsock_path =
    Log.info (fun f ->
        f "starting port forwarding server on port_control_url:%s vsock_path:%s"
          port_control_url vsock_path);
    (* Start the 9P port forwarding server *)
    Connect_unix.vsock_path := vsock_path;
    (match max_connections with
    | None   -> ()
    | Some _ ->
      Log.warn (fun f ->
          f "The argument max-connections is nolonger supported, use the \
             database key slirp/max-connections instead"));
    Host.Sockets.set_max_connections max_connections;
    let uri = Uri.of_string port_control_url in
    Mclock.connect () >>= fun clock ->
    match Uri.scheme uri with
    | Some "hyperv-connect" ->
      let module Ports = Active_list.Make(Forward_hvsock) in
      let fs = Ports.make clock in
      Ports.set_context fs "";
      let module Server = Protocol_9p.Server.Make(Log9P)(HV)(Ports) in
      let sockaddr = hvsock_addr_of_uri ~default_serviceid:ports_serviceid uri in
      Connect_hvsock.set_port_forward_addr sockaddr;
      hvsock_connect_forever port_control_url sockaddr (fun fd ->
          let flow = HV.connect fd in
          Server.connect fs flow () >>= function
          | Error (`Msg m) ->
            Log.err (fun f -> f "failed to establish 9P connection: %s" m);
            Lwt.return ()
          | Ok server -> Server.after_disconnect server)
    | _ ->
      let module Ports = Active_list.Make(Forward_unix) in
      let fs = Ports.make clock in
      Ports.set_context fs vsock_path;
      let module Server =
        Protocol_9p.Server.Make(Log9P)(Host.Sockets.Stream.Unix)(Ports)
      in
      unix_listen port_control_url >|= fun port_s ->
      Host.Sockets.Stream.Unix.listen port_s (fun conn ->
          Server.connect fs conn () >>= function
          | Error (`Msg m) ->
            Log.err (fun f -> f "failed to establish 9P connection: %s" m);
            Lwt.return ()
          | Ok server ->
            Server.after_disconnect server)

  let main_t
      configuration
      socket_url port_control_url introspection_url diagnostics_url
      vsock_path db_path db_branch hosts
      listen_backlog debug
    =
    (* Write to stdout if expicitly requested [debug = true] or if the
       environment variable DEBUG is set *)
    let env_debug =
      try ignore @@ Unix.getenv "DEBUG"; true
      with Not_found -> false
    in
    if debug || env_debug then begin
      Logs.set_reporter (Logs_fmt.reporter ());
      Log.info (fun f ->
          f "Logging to stdout (stdout:%b DEBUG:%b)" debug env_debug);
    end else begin
      if Sys.os_type = "Win32" then begin
        let h = Eventlog.register "Docker.exe" in
        Logs.set_reporter (Log_eventlog.reporter ~eventlog:h ());
        Log.info (fun f -> f "Logging to the Windows event log")
      end else begin
        let facility = Filename.basename Sys.executable_name in
        let client = Asl.Client.create ~ident:"Docker" ~facility () in
        Logs.set_reporter (Log_asl.reporter ~client ());
        let dev_null = Unix.openfile "/dev/null" [ Unix.O_WRONLY ] 0 in
        Unix.dup2 dev_null Unix.stdout;
        Unix.dup2 dev_null Unix.stderr;
        Log.info (fun f -> f "Logging to Apple System Log")
      end
    end;
    Log.info (fun f -> f "Setting handler to ignore all SIGPIPE signals");
    (* This will always succeed on Mac but will raise Illegal_argument
       on Windows. Happily on Windows there is no such thing as
       SIGPIPE so it's safe to catch the exception and throw it
       away. *)
    (try Sys.set_signal Sys.sigpipe Sys.Signal_ignore
    with Invalid_argument _ -> ());
    Log.info (fun f ->
        f "vpnkit version %%VERSION%% from %%VCS_COMMIT_ID%%"
    );

    Log.info (fun f -> f "System SOMAXCONN is %d" !Utils.somaxconn);
    Utils.somaxconn :=
      (match listen_backlog with None -> !Utils.somaxconn | Some x -> x);
    Log.info (fun f -> f "Will use a listen backlog of %d" !Utils.somaxconn);

    Printexc.record_backtrace true;

    let etc_hosts_watch = match HostsFile.watch ~path:hosts () with
    | Ok watch       -> Some watch
    | Error (`Msg m) ->
      Log.err (fun f -> f "Failed to watch hosts file %s: %s" hosts m);
      None
    in

    Lwt.async_exception_hook := (fun exn ->
        Log.err (fun f ->
            f "Lwt.async failure %a: %s" Fmt.exn exn (Printexc.get_backtrace ()))
      );

    Lwt.async (fun () ->
        log_exception_continue "start_port_server" (fun () ->
            start_port_forwarding port_control_url configuration.Configuration.max_connections vsock_path
          )
      );

    Mclock.connect () >>= fun clock ->
    let vnet_switch = Vnet.create () in

    let config = match db_path with
    | Some db_path ->
      let reconnect () =
        let open Lwt_result.Infix in
        Host.Sockets.Stream.Unix.connect db_path >>= fun x ->
        Lwt_result.return x
      in
      Some (Config.create ~reconnect ~branch:db_branch ())
    | None ->
      Log.warn (fun f ->
          f "no database: using hardcoded network configuration values");
      None
    in

    let uri = Uri.of_string socket_url in

    match Uri.scheme uri with
    | Some "hyperv-connect" ->
      let module Slirp_stack =
        Slirp.Make(Config)(Vmnet.Make(HV))(Dns_policy)
          (Mclock)(Stdlibrandom)(Vnet)
      in
      let sockaddr =
        hvsock_addr_of_uri ~default_serviceid:ethernet_serviceid
          (Uri.of_string socket_url)
      in
      ( match config with
      | Some config -> Slirp_stack.create_from_active_config clock vnet_switch configuration config
      | None -> Slirp_stack.create_static clock vnet_switch configuration
      ) >>= fun stack_config ->
      hvsock_connect_forever socket_url sockaddr (fun fd ->
          let conn = HV.connect fd in
          Slirp_stack.connect stack_config conn >>= fun stack ->
          Log.info (fun f -> f "stack connected");
          start_introspection introspection_url (Slirp_stack.filesystem stack);
          start_diagnostics diagnostics_url @@ Slirp_stack.diagnostics stack;
          Slirp_stack.after_disconnect stack >|= fun () ->
          Log.info (fun f -> f "stack disconnected"))

    | _ ->
      let module Slirp_stack =
        Slirp.Make(Config)(Vmnet.Make(Host.Sockets.Stream.Unix))(Dns_policy)
          (Mclock)(Stdlibrandom)(Vnet)
      in
      unix_listen socket_url >>= fun server ->
      ( match config with
      | Some config -> Slirp_stack.create_from_active_config clock vnet_switch configuration config
      | None -> Slirp_stack.create_static clock vnet_switch configuration
      ) >>= fun stack_config ->
      Host.Sockets.Stream.Unix.listen server (fun conn ->
          Slirp_stack.connect stack_config conn >>= fun stack ->
          Log.info (fun f -> f "stack connected");
          start_introspection introspection_url (Slirp_stack.filesystem stack);
          start_diagnostics diagnostics_url @@ Slirp_stack.diagnostics stack;
          Slirp_stack.after_disconnect stack >|= fun () ->
          Log.info (fun f -> f "stack disconnected")
        );
      let wait_forever, _ = Lwt.task () in
      wait_forever >|= fun () ->
      match etc_hosts_watch with
      | Some watch -> HostsFile.unwatch watch
      | None       -> ()

  let main
      socket_url port_control_url introspection_url diagnostics_url
      max_connections vsock_path db_path db_branch dns hosts host_names
      listen_backlog port_max_idle_time debug
      server_macaddr domain allowed_bind_addresses docker highest_ip
    =
    let host_names = List.map Dns.Name.of_string @@ Astring.String.cuts ~sep:"," host_names in
    let dns, resolver = match dns with
    | None -> Configuration.no_dns_servers, Configuration.default_resolver
    | Some ip ->
      let open Dns_forward.Config in
      let servers = Server.Set.of_list [
          { Server.address = { Address.ip = Ipaddr.of_string_exn ip; port = 53 };
            zones = Domain.Set.empty; timeout_ms = Some 2000; order = 0;
          }
        ] in
      { servers; search = []; assume_offline_after_drops = None }, `Upstream in
    let server_macaddr = Macaddr.of_string_exn server_macaddr in
    let allowed_bind_addresses = Configuration.Parse.ipv4_list [] allowed_bind_addresses in
    let docker = Ipaddr.V4.of_string_exn docker in
    let highest_ip = Ipaddr.V4.of_string_exn highest_ip in
    let configuration = {
      Configuration.default with
      max_connections;
      port_max_idle_time;
      host_names;
      dns;
      resolver;
      server_macaddr;
      domain;
      allowed_bind_addresses;
      docker;
      highest_ip;
    } in
    match socket_url with
      | None ->
        Printf.fprintf stderr "Please provide an --ethernet argument\n"
      | Some socket_url ->
    Host.Main.run
      (main_t configuration socket_url port_control_url introspection_url diagnostics_url
         vsock_path db_path db_branch hosts
         listen_backlog debug);

open Cmdliner

let socket =
  let doc =
    Arg.info ~doc:
      "The address on the host for the VM ethernet connection. Possible values \
       include:  hyperv-connect://vmid/serviceid to connect to a specific \
       Hyper-V 'serviceid' on VM 'vmid'; hyperv-connect://vmid to connect to \
       the default Hyper-V 'serviceid' on  VM 'vmid'; \
       /var/tmp/com.docker.slirp.socket to listen on a Unix domain socket for \
       incoming connections."
      [ "ethernet" ]
  in
  Arg.(value & opt (some string) None doc)

let port_control_path =
  let doc =
    Arg.info ~doc:
      "The address on the host for the 9P filesystem needed to control host \
       port forwarding. Possible values include: \
       hyperv-connect://vmid/serviceid to connect to a specific Hyper-V \
       'serviceid' on VM 'vmid'; hyperv-connect://vmid to connect to the \
       default Hyper-V 'serviceid' on VM 'vmid'; \
       /var/tmp/com.docker.port.socket to listen on a Unix domain socket for \
       incoming connections."
      [ "port" ]
  in
  Arg.(value & opt string "" doc)

let introspection_path =
  let doc =
    Arg.info ~doc:
      "The address on the host on which to serve a 9P filesystem which exposes \
       internal daemon state. So far this allows active network connections to \
       be listed, to help debug problems with the connection tracking. \
       Possible values include: \
       /var/tmp/com.docker.slirp.introspection.socket to listen on a Unix \
       domain socket for incoming connections or \
       \\\\\\\\.\\\\pipe\\\\introspection to listen on a Windows named pipe"
      [ "introspection" ]
  in
  Arg.(value & opt string "" doc)

let diagnostics_path =
  let doc =
    Arg.info ~doc:
      "The address on the host on which to serve a .tar file containing \
       internal daemon diagnostics which can be used to help debug problems \
       Possible values include: \
       /var/tmp/com.docker.slirp.diagnostics.socket to listen on a Unix domain \
       socket for incoming connections or \
       \\\\\\\\.\\\\pipe\\\\diagnostics to listen on a Windows named pipe"
      [ "diagnostics" ]
  in
  Arg.(value & opt string "" doc)

let max_connections =
  let doc =
    Arg.info ~doc:
      "This argument is deprecated: use the database key slirp/max-connections \
       instead." [ "max-connections" ]
  in
  Arg.(value & opt (some int) None doc)

let vsock_path =
  let doc =
    Arg.info ~doc:
      "Path of the Unix domain socket used to setup virtio-vsock connections \
       to the VM." [ "vsock-path" ] ~docv:"VSOCK"
  in
  Arg.(value & opt string "" doc)

let db_path =
  let doc =
    Arg.info ~doc:
      "The address on the host for the datakit database. \
       Possible values include: \
       file:///var/tmp/foo to connect to Unix domain socket /var/tmp/foo; \
       tcp://host:port to connect to over TCP/IP; \
       \\\\\\\\.\\\\pipe\\\\irmin to connect to a named pipe on Windows."
      ["db"]
  in
  Arg.(value & opt (some string) None doc)

let db_branch =
  let doc =
    Arg.info ~doc:
      "The database branch which contains the configuration information. \
       The default is `master`."
      ["branch"]
  in
  Arg.(value & opt string "master" doc)

let dns =
  let doc =
    Arg.info ~doc:
      "IP address of upstream DNS server" ["dns"]
  in
  Arg.(value & opt (some string) None doc)

let hosts =
  let doc =
    Arg.info ~doc:
      "Path to /etc/hosts file" ["hosts"]
  in
  Arg.(value & opt string Hosts.default_etc_hosts_path doc)

let host_names =
  let doc =
    Arg.info ~doc:
      "Comma-separated list of DNS names to map to the Host's virtual IP"
      ["host-names"]
  in
  Arg.(value & opt string "vpnkit.host" doc)

let listen_backlog =
  let doc = "Specify a maximum listen(2) backlog. If no override is specified \
             then we will use SOMAXCONN." in
  Arg.(value & opt (some int) None & info [ "listen-backlog" ] ~doc)

let port_max_idle_time =
  let doc = "Idle time to wait before timing out and disconnecting switch ports." in
  Arg.(value & opt int 30 & info [ "port-max-idle-time" ] ~doc)

let debug =
  let doc = "Verbose debug logging to stdout" in
  Arg.(value & flag & info [ "debug" ] ~doc)

let server_macaddr =
  let doc = "Ethernet MAC for the host to use" in
  Arg.(value & opt string (Macaddr.to_string Configuration.default_server_macaddr) & info [ "server-macaddr" ] ~doc)

let domain =
  let doc = "Domain name to include in DHCP offers" in
  Arg.(value & opt string Configuration.default_domain & info [ "domain" ] ~doc)

let allowed_bind_addresses =
  let doc =
    Arg.info ~doc:
      "List of interfaces where container ports may be exposed. For example \
       to limit port exposure to localhost, use `127.0.0.1`. The default setting \
       allows ports to be exposed on any interface."
      [ "allowed-bind-addresses" ]
  in
  Arg.(value & opt string "0.0.0.0" doc)

let docker =
  let doc =
    Arg.info ~doc:
      "IP address of the vpnkit gateway"
      [ "gateway-ip" ]
  in
  Arg.(value & opt string (Ipaddr.V4.to_string Configuration.default_docker) doc)

let highest_ip =
  let doc =
    Arg.info ~doc:
      "Highest IP address to hand out by DHCP"
      [ "highest-dhcp-ip" ]
  in
  Arg.(value & opt string (Ipaddr.V4.to_string Configuration.default_highest_ip) doc)

let command =
  let doc = "proxy TCP/IP connections from an ethernet link via sockets" in
  let man =
    [`S "DESCRIPTION";
     `P "Terminates TCP/IP and UDP/IP connections from a client and proxy the\
         flows via userspace sockets"]
  in
  Term.(pure main
        $ socket $ port_control_path $ introspection_path $ diagnostics_path
        $ max_connections $ vsock_path $ db_path $ db_branch $ dns $ hosts
        $ host_names $ listen_backlog $ port_max_idle_time $ debug
        $ server_macaddr $ domain $ allowed_bind_addresses $ docker
        $ highest_ip ),
  Term.info (Filename.basename Sys.argv.(0)) ~version:"%%VERSION%%" ~doc ~man

let () =
  Printexc.record_backtrace true;

  Term.exit @@ Term.eval command

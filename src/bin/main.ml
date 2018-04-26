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
      try
        let fd = file_descr_of_int @@ int_of_string i in
        Lwt.return (Ok (Host.Sockets.Stream.Unix.of_bound_fd fd))
      with _ ->
        Log.err (fun f -> f "Failed to parse command-line argument [%s] expected fd:<int>" path);
        Lwt.return (Error (`Msg "Failed to parase command-line argument"))
    end else
      Lwt.catch
        (fun () ->
          Host.Sockets.Stream.Unix.bind path
          >>= fun s ->
          Lwt.return (Ok s)
        ) (fun e ->
          Log.err (fun f -> f "Failed to call Stream.Unix.bind \"%s\": %s" path (Printexc.to_string e));
          Lwt.return (Error (`Msg  "Failed to bind to Unix domain socket"))
        )

  let hvsock_create () =
    let rec loop () =
      match HV.Hvsock.create () with
      | x -> Lwt.return x
      | exception e ->
        Log.err (fun f -> f "Caught %s while creating Hyper-V socket" (Printexc.to_string e));
        Host.Time.sleep_ns (Duration.of_sec 1)
        >>= fun () ->
        loop () in
    loop ()

  let hvsock_listen sockaddr callback =
    Log.info (fun f ->
      f "Listening on %s:%s" (Hvsock.string_of_vmid sockaddr.Hvsock.vmid)
        sockaddr.Hvsock.serviceid);
    let rec aux () =
      hvsock_create ()
      >>= fun socket ->
      Lwt.catch (fun () ->
        HV.Hvsock.listen socket 5;
        let rec accept_forever () =
          HV.Hvsock.accept socket
          >>= fun (t, clientaddr) ->
          Log.info (fun f -> f "Accepted connection from %s:%s "
            (Hvsock.string_of_vmid clientaddr.Hvsock.vmid)
            clientaddr.Hvsock.serviceid);
          Lwt.async (fun () -> callback t);
          accept_forever () in
        accept_forever ()
      ) (fun e ->
          Log.warn (fun f -> f "Caught %s while listening on %s:%s"
            (Printexc.to_string e)
            (Hvsock.string_of_vmid sockaddr.Hvsock.vmid)
            sockaddr.Hvsock.serviceid);
          log_exception_continue "HV.Hvsock.close" (fun () -> HV.Hvsock.close socket)
      )
      >>= fun () ->
      aux () in
    aux ()

  let hvsock_connect_forever url sockaddr callback =
    Log.info (fun f ->
        f "Connecting to %s:%s" (Hvsock.string_of_vmid sockaddr.Hvsock.vmid)
          sockaddr.Hvsock.serviceid);
    let rec aux () =
      hvsock_create ()
      >>= fun socket ->
      Lwt.catch (fun () ->
          HV.Hvsock.connect ~timeout_ms:300 socket sockaddr >>= fun () ->
          Log.info (fun f -> f "AF_HVSOCK connected successfully");
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
        f "There is no introspection server requested. See the --introspection argument")
    else Lwt.async (fun () ->
        log_exception_continue
          ("Starting introspection server on: " ^ introspection_url)
          (fun () ->
             Log.info (fun f ->
                 f "Starting introspection server on: %s" introspection_url);
             let module Server = Fs9p.Make(Host.Sockets.Stream.Unix) in
             unix_listen introspection_url
             >>= function
             | Error (`Msg m) ->
               Log.err (fun f -> f "Failed to start introspection server because: %s" m);
               Lwt.return_unit
             | Ok s ->
               Host.Sockets.Stream.Unix.disable_connection_tracking s;
               Host.Sockets.Stream.Unix.listen s (fun flow ->
                 Server.accept ~root ~msg:introspection_url flow >>= function
                 | Error (`Msg m) ->
                   Log.err (fun f ->
                       f "Failed to establish 9P connection: %s" m);
                   Lwt.return ()
                 | Ok () ->
                   Lwt.return_unit
               );
               Lwt.return_unit))

  let start_diagnostics diagnostics_url flow_cb =
    if diagnostics_url = ""
    then Log.info (fun f ->
        f "No diagnostics server requested. See the --diagnostics argument")
    else Lwt.async (fun () ->
        log_exception_continue
          ("Starting diagnostics server on: " ^ diagnostics_url)
          (fun () ->
             Log.info (fun f ->
                 f "Starting diagnostics server on: %s" diagnostics_url);
             unix_listen diagnostics_url
             >>= function
             | Error (`Msg m) ->
               Log.err (fun f -> f "Failed to start diagnostics server because: %s" m);
               Lwt.return_unit
             | Ok s ->
               Host.Sockets.Stream.Unix.disable_connection_tracking s;
               Host.Sockets.Stream.Unix.listen s flow_cb;
               Lwt.return_unit))

  module type Forwarder = sig
    include Protocol_9p.Filesystem.S
    val make: Mclock.t -> t
  end

  (* Create one instance of the Active_list functor per-process. The list of
     current port forwards is stored in a map inside the module (not in the
     `type t` returned from `make`) *)
  let port_forwarder =
      if Sys.os_type = "Unix"
        then (module Active_list.Make(Forward_unix) : Forwarder)
        else (module Active_list.Make(Forward_hvsock) : Forwarder)

  let start_port_forwarding port_control_url max_connections vsock_path =
    Log.info (fun f ->
        f "Starting port forwarding server on port_control_url:\"%s\" vsock_path:\"%s\""
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
    let module Ports = (val port_forwarder: Forwarder) in
    let fs = Ports.make clock in

    match Uri.scheme uri with
    | Some ("hyperv-connect" | "hyperv-listen") ->
      let module Server = Protocol_9p.Server.Make(Log9P)(HV)(Ports) in
      let sockaddr = hvsock_addr_of_uri ~default_serviceid:ports_serviceid uri in
      Connect_hvsock.set_port_forward_addr sockaddr;
      let callback fd =
        let flow = HV.connect fd in
        Server.connect fs flow () >>= function
        | Error (`Msg m) ->
          Log.err (fun f -> f "Failed to establish 9P connection: %s" m);
          Lwt.return ()
        | Ok server -> Server.after_disconnect server in
      if Uri.scheme uri = Some "hyperv-connect"
      then hvsock_connect_forever port_control_url sockaddr callback
      else hvsock_listen sockaddr callback
    | _ ->
      let module Server =
        Protocol_9p.Server.Make(Log9P)(Host.Sockets.Stream.Unix)(Ports)
      in
      unix_listen port_control_url
      >>= function
      | Error (`Msg m) ->
        Log.err (fun f -> f "Failed to start port forwarding server because: %s" m);
        Lwt.return_unit
      | Ok port_s ->
        Host.Sockets.Stream.Unix.listen port_s (fun conn ->
          Server.connect fs conn () >>= function
          | Error (`Msg m) ->
            Log.err (fun f -> f "Failed to establish 9P connection: %s" m);
            Lwt.return_unit
          | Ok server ->
            Server.after_disconnect server);
        Lwt.return_unit

  let main_t
      configuration
      socket_url port_control_urls introspection_urls diagnostics_urls
      vsock_path db_path db_branch hosts
      listen_backlog
    =
    Log.info (fun f -> f "Setting handler to ignore all SIGPIPE signals");
    (* This will always succeed on Mac but will raise Illegal_argument
       on Windows. Happily on Windows there is no such thing as
       SIGPIPE so it's safe to catch the exception and throw it
       away. *)
    (try Sys.set_signal Sys.sigpipe Sys.Signal_ignore
    with Invalid_argument _ -> ());
    Log.info (fun f ->
        f "Version is %s" Version.git
    );

    Log.info (fun f -> f "System SOMAXCONN is %d" !Utils.somaxconn);
    Utils.somaxconn :=
      (match listen_backlog with None -> !Utils.somaxconn | Some x -> x);
    Log.info (fun f -> f "Will use a listen backlog of %d" !Utils.somaxconn);

    Printexc.record_backtrace true;

    let () = match HostsFile.watch ~path:hosts () with
    | Ok _       -> ()
    | Error (`Msg m) ->
      Log.err (fun f -> f "Failed to watch hosts file %s: %s" hosts m);
      ()
    in

    List.iter
      (fun url ->
        Lwt.async (fun () ->
            log_exception_continue ("Starting the 9P port control filesystem on " ^ url) (fun () ->
                start_port_forwarding url configuration.Configuration.max_connections vsock_path
              )
          )
      ) port_control_urls;

    Mclock.connect () >>= fun clock ->
    let vnet_switch = Vnet.create () in

    let config = match db_path with
    | Some db_path ->
      let reconnect () =
        let open Lwt_result.Infix in
        Log.info (fun f -> f "Connecting to database on %s" db_path);
        Host.Sockets.Stream.Unix.connect db_path >>= fun x ->
        Lwt_result.return x
      in
      Some (Config.create ~reconnect ~branch:db_branch ())
    | None ->
      Log.warn (fun f ->
          f "There is no database: using hardcoded network configuration values");
      None
    in

    let uri = Uri.of_string socket_url in

    match Uri.scheme uri with
    | Some ("hyperv-connect"|"hyperv-listen") ->
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
      let callback fd =
        let conn = HV.connect fd in
        Slirp_stack.connect stack_config conn >>= fun stack ->
        Log.info (fun f -> f "TCP/IP stack connected");
        List.iter (fun url ->
          start_introspection url (Slirp_stack.filesystem stack)
        ) introspection_urls;
        List.iter (fun url ->
          start_diagnostics url @@ Slirp_stack.diagnostics stack
        ) diagnostics_urls;
        Slirp_stack.after_disconnect stack >|= fun () ->
        Log.info (fun f -> f "TCP/IP stack disconnected") in
      if Uri.scheme uri = Some "hyperv-connect"
      then hvsock_connect_forever socket_url sockaddr callback
      else hvsock_listen sockaddr callback
    | _ ->
      let module Slirp_stack =
        Slirp.Make(Config)(Vmnet.Make(Host.Sockets.Stream.Unix))(Dns_policy)
          (Mclock)(Stdlibrandom)(Vnet)
      in
      unix_listen socket_url
      >>= function
      | Error (`Msg m) ->
        Log.err (fun f -> f "Failed to listen on ethernet socket because: %s" m);
        Lwt.return_unit
      | Ok server ->
      ( match config with
      | Some config -> Slirp_stack.create_from_active_config clock vnet_switch configuration config
      | None -> Slirp_stack.create_static clock vnet_switch configuration
      ) >>= fun stack_config ->
      Host.Sockets.Stream.Unix.listen server (fun conn ->
          Slirp_stack.connect stack_config conn >>= fun stack ->
          Log.info (fun f -> f "TCP/IP stack connected");
          List.iter (fun url ->
            start_introspection url (Slirp_stack.filesystem stack);
          ) introspection_urls;
          List.iter (fun url ->
            start_diagnostics url @@ Slirp_stack.diagnostics stack
          ) diagnostics_urls;
          Slirp_stack.after_disconnect stack >|= fun () ->
          Log.info (fun f -> f "TCP/IP stack disconnected")
        );
      let wait_forever, _ = Lwt.task () in
      wait_forever

  let main
      socket_url port_control_urls introspection_urls diagnostics_urls
      max_connections vsock_path db_path db_branch dns http hosts host_names gateway_names
      vm_names listen_backlog port_max_idle_time debug
      server_macaddr domain allowed_bind_addresses gateway_ip host_ip lowest_ip highest_ip
      dhcp_json_path mtu udpv4_forwards log_destination
    =
    let level =
      let env_debug =
        try ignore @@ Unix.getenv "DEBUG"; true
        with Not_found -> false
      in
      if debug || env_debug then Some Logs.Debug else Some Logs.Info in
    Logging.setup log_destination level;

    if Sys.os_type = "Unix" then begin
      Log.info (fun f -> f "Increasing preemptive thread pool size to 1024 threads");
      Uwt_preemptive.set_bounds (0, 1024);
    end;

    let host_names = List.map Dns.Name.of_string @@ Astring.String.cuts ~sep:"," host_names in
    let gateway_names = List.map Dns.Name.of_string @@ Astring.String.cuts ~sep:"," gateway_names in
    let vm_names = List.map Dns.Name.of_string @@ Astring.String.cuts ~sep:"," vm_names in

    let dns_path, resolver = match dns with
    | None -> None, Configuration.default_resolver
    | Some file -> Some file, `Upstream in
    let server_macaddr = Macaddr.of_string_exn server_macaddr in
    let allowed_bind_addresses = Configuration.Parse.ipv4_list [] allowed_bind_addresses in
    let gateway_ip = Ipaddr.V4.of_string_exn gateway_ip in
    let host_ip = Ipaddr.V4.of_string_exn host_ip in
    let lowest_ip = Ipaddr.V4.of_string_exn lowest_ip in
    let highest_ip = Ipaddr.V4.of_string_exn highest_ip in
    let udpv4_forwards =
      List.map (fun x -> match Stringext.split ~on:':' x with
        | [ local_port; remote_ip; remote_port ] ->
          let local_port = int_of_string local_port in
          let remote_ip = Ipaddr.V4.of_string_exn remote_ip in
          let remote_port = int_of_string remote_port in
          local_port, (remote_ip, remote_port)
        | _ ->
          failwith "Failed to parse UDPv4 forwards: expected <local-port>:<remote IP>:<remote port>"
      ) (Stringext.split ~on:',' udpv4_forwards) in
    let configuration = {
      Configuration.default with
      max_connections;
      port_max_idle_time;
      host_names;
      gateway_names;
      vm_names;
      dns = Configuration.no_dns_servers;
      dns_path;
      http_intercept_path = http;
      resolver;
      server_macaddr;
      domain;
      allowed_bind_addresses;
      gateway_ip;
      host_ip;
      lowest_ip;
      highest_ip;
      dhcp_json_path;
      mtu;
      udpv4_forwards;
    } in
    match socket_url with
      | None ->
        Printf.fprintf stderr "Please provide an --ethernet argument\n"
      | Some socket_url ->
    try
      Host.Main.run
        (main_t configuration socket_url port_control_urls introspection_urls diagnostics_urls
          vsock_path db_path db_branch hosts
          listen_backlog);
    with e ->
      Log.err (fun f -> f "Host.Main.run caught exception %s: %s" (Printexc.to_string e) (Printexc.get_backtrace ()))
open Cmdliner

let socket =
  let doc =
    Arg.info ~doc:
      "The address on the host for the VM ethernet connection. Possible values \
       include:  hyperv-connect://vmid/serviceid to connect to a specific \
       Hyper-V 'serviceid' on VM 'vmid'; hyperv-connect://vmid to connect to \
       the default Hyper-V 'serviceid' on  VM 'vmid'; \
       hyperv-listen://vmid/serviceid to accept incoming Hyper-V connections \
       on `serviceid` and `vmid`; hyperv-listen://vmid to accept connections \
       to the default Hyper-V `serviceid` on VM `vmid`; \
       /var/tmp/com.docker.slirp.socket to listen on a Unix domain socket for \
       incoming connections."
      [ "ethernet" ]
  in
  Arg.(value & opt (some string) None doc)

let port_control_urls =
  let doc =
    Arg.info ~doc:
      "The address on the host for the 9P filesystem needed to control host \
       port forwarding. Possible values include: \
       hyperv-connect://vmid/serviceid to connect to a specific Hyper-V \
       'serviceid' on VM 'vmid'; hyperv-connect://vmid to connect to the \
       default Hyper-V 'serviceid' on VM 'vmid'; \
       hyperv-listen://vmid/serviceid to accept incoming Hyper-V connections \
       on `serviceid` and `vmid`; hyperv-listen://vmid to accept connections \
       to the default Hyper-V `serviceid` on VM `vmid`; \
       /var/tmp/com.docker.port.socket to listen on a Unix domain socket for \
       incoming connections."
      [ "port" ]
  in
  Arg.(value & opt_all string [] doc)

let introspection_urls =
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
  Arg.(value & opt_all string [] doc)

let diagnostics_urls =
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
  Arg.(value & opt_all string [] doc)

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
      "File containing DNS configuration. The file consists of a series of lines, \
      each line starting either with a # comment or containing a keyword followed by \
      arguments. For example 'nameserver 8.8.8.8' or 'timeout 5000'.\
      " ["dns"]
  in
  Arg.(value & opt (some string) None doc)

let http =
  let doc =
    Arg.info ~doc:
      "File containing transparent HTTP redirection configuration.\
      If this argument is given, then outgoing connections to port 80 (HTTP) \
      and 443 (HTTPS) are transparently redirected to the proxies mentioned \
      in the configuration file. The configuration file is in .json format as \
      follows: `{\"http\": \"host:3128\",\
        \"https\": \"host:3128\",\
        \"exclude\": \"*.local\"\
      }`\
      " ["http"]
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
  Arg.(value & opt string "host.internal" doc)

let gateway_names =
  let doc =
    Arg.info ~doc:
      "Comma-separated list of DNS names to map to the gateway's virtual IP"
      ["gateway-names"]
  in
  Arg.(value & opt string "gateway.internal" doc)

let vm_names =
  let doc =
    Arg.info ~doc:
      "Comma-separated list of DNS names to map to the VM's virtual IP"
      [ "vm-names" ]
  in
  Arg.(value & opt string "vm.internal" doc)

let listen_backlog =
  let doc = "Specify a maximum listen(2) backlog. If no override is specified \
             then we will use SOMAXCONN." in
  Arg.(value & opt (some int) None & info [ "listen-backlog" ] ~doc)

let port_max_idle_time =
  let doc = "Idle time to wait before timing out and disconnecting switch ports." in
  Arg.(value & opt int Configuration.default_port_max_idle_time & info [ "port-max-idle-time" ] ~doc)

let debug =
  let doc = "Verbose debug logging to stdout" in
  Arg.(value & flag & info [ "debug" ] ~doc)

let server_macaddr =
  let doc = "Ethernet MAC for the host to use" in
  Arg.(value & opt string (Macaddr.to_string Configuration.default_server_macaddr) & info [ "server-macaddr" ] ~doc)

let domain =
  let doc = "Domain name to include in DHCP offers" in
  Arg.(value & opt (some string) None & info [ "domain" ] ~doc)

let allowed_bind_addresses =
  let doc =
    Arg.info ~doc:
      "List of interfaces where container ports may be exposed. For example \
       to limit port exposure to localhost, use `127.0.0.1`. The default setting \
       allows ports to be exposed on any interface."
      [ "allowed-bind-addresses" ]
  in
  Arg.(value & opt string "0.0.0.0" doc)

let gateway_ip =
  let doc =
    Arg.info ~doc:
      "IP address of the vpnkit gateway"
      [ "gateway-ip" ]
  in
  Arg.(value & opt string (Ipaddr.V4.to_string Configuration.default_gateway_ip) doc)

let host_ip =
  let doc =
    Arg.info ~doc:
      "IP address which represents the host. Connections to this IP will be forwarded to localhost on the host."
      [ "host-ip" ]
  in
  Arg.(value & opt string (Ipaddr.V4.to_string Configuration.default_host_ip) doc)

let lowest_ip =
  let doc =
    Arg.info ~doc:
      "Lowest IP address to hand out by DHCP"
      [ "lowest-ip" ]
  in
  Arg.(value & opt string (Ipaddr.V4.to_string Configuration.default_lowest_ip) doc)

let highest_ip =
  let doc =
    Arg.info ~doc:
      "Highest IP address to hand out by DHCP"
      [ "highest-ip" ]
  in
  Arg.(value & opt string (Ipaddr.V4.to_string Configuration.default_highest_ip) doc)

let dhcp_json_path =
  let doc =
    Arg.info ~doc:
      "Path of DHCP configuration file"
      [ "dhcp-path" ]
  in
  Arg.(value & opt (some file) None doc)

let mtu =
  let doc =
    Arg.info ~doc:
      "Maximum Transfer Unit of the ethernet links"
      [ "mtu" ]
  in
  Arg.(value & opt int Configuration.default_mtu doc)

let udpv4_forwards =
  let doc =
    Arg.info ~doc:
      "Configure UDPv4 forwards from the gateway address to remote systems.
       The argument is a comma-separated list of <local port>:<remote IPv4>:<remote port>"
       [ "udpv4-forwards" ]
  in
  Arg.(value & opt string "" doc)

let command =
  let doc = "proxy TCP/IP connections from an ethernet link via sockets" in
  let man =
    [`S "DESCRIPTION";
     `P "Terminates TCP/IP and UDP/IP connections from a client and proxy the\
         flows via userspace sockets"]
  in
  Term.(pure main
        $ socket $ port_control_urls $ introspection_urls $ diagnostics_urls
        $ max_connections $ vsock_path $ db_path $ db_branch $ dns $ http $ hosts
        $ host_names $ gateway_names $ vm_names $ listen_backlog $ port_max_idle_time $ debug
        $ server_macaddr $ domain $ allowed_bind_addresses $ gateway_ip $ host_ip
        $ lowest_ip $ highest_ip $ dhcp_json_path $ mtu $ udpv4_forwards $ Logging.log_destination),
  Term.info (Filename.basename Sys.argv.(0)) ~version:"%%VERSION%%" ~doc ~man

let () =
  Printexc.record_backtrace true;

  Lwt.async_exception_hook := (fun exn ->
  Log.err (fun f ->
      f "Lwt.async failure %a: %s" Fmt.exn exn (Printexc.get_backtrace ()))
  );
  Term.exit @@ Term.eval command

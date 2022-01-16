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
       Log.warn (fun f -> f "%s: failed with %a" description Fmt.exn e);
       Lwt.return ()
    )

let ethernet_serviceid = "30D48B34-7D27-4B0B-AAAF-BBBED334DD59"
let ports_serviceid = "0B95756A-9985-48AD-9470-78E060895BE7"

let hvsock_addr_of_uri ~default_serviceid uri =
  (* hyperv://vmid/serviceid *)
  let vmid = match Uri.host uri with
  | None   -> Hvsock.Af_hyperv.Loopback
  | Some x ->
    begin match Uuidm.of_string x with
    | Some x -> Hvsock.Af_hyperv.Id x
    | None -> failwith (Printf.sprintf "In uri %s serviceid %s is not a GUID" (Uri.to_string uri) x)
    end
  in
  let serviceid =
    let p = Uri.path uri in
    if p = ""
    then default_serviceid
    (* trim leading / *)
    else if String.length p > 0 then String.sub p 1 (String.length p - 1) else p
  in
  { Hvsock.Af_hyperv.vmid; serviceid }

  module Vnet = Basic_backend.Make
  module Connect_unix = Connect.Unix
  module Connect_hvsock = Connect.Hvsock
  module Bind = Bind.Make(Host.Sockets)
  module Dns_policy = Hostnet_dns.Policy(Host.Files)
  module Forward_unix = Forward.Make(Mclock)(Connect_unix)(Bind)
  module Forward_hvsock = Forward.Make(Mclock)(Connect_hvsock)(Bind)
  module HV = Hvsock_lwt.Flow.Make(Host.Time)(Host.Fn)(Hvsock.Af_hyperv)
  module HV_generic = Hvsock_lwt.Flow.Make(Host.Time)(Host.Fn)(Hvsock.Socket)
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
      match HV.Socket.create () with
      | x -> Lwt.return x
      | exception e ->
        Log.err (fun f -> f "Caught %s while creating Hyper-V socket" (Printexc.to_string e));
        Host.Time.sleep_ns (Duration.of_sec 1)
        >>= fun () ->
        loop () in
    loop ()

  let hvsock_listen sockaddr callback =
    Log.info (fun f -> f "Listening on %s" (Hvsock.Af_hyperv.string_of_sockaddr sockaddr));
    let rec aux () =
      hvsock_create ()
      >>= fun socket ->
      Lwt.catch (fun () ->
        HV.Socket.bind socket sockaddr;
        HV.Socket.listen socket 5;
        let rec accept_forever () =
          HV.Socket.accept socket
          >>= fun (t, clientaddr) ->
          Log.info (fun f -> f "Accepted connection from %s" (Hvsock.Af_hyperv.string_of_sockaddr clientaddr));
          Lwt.async (fun () -> callback t);
          accept_forever () in
        accept_forever ()
      ) (fun e ->
          Log.warn (fun f -> f "Caught %s while listening on %s"
            (Printexc.to_string e)
            (Hvsock.Af_hyperv.string_of_sockaddr sockaddr));
          log_exception_continue "HV.Socket.close" (fun () -> HV.Socket.close socket)
          >>= fun () ->
          Host.Time.sleep_ns (Duration.of_sec 1)
      )
      >>= fun () ->
      aux () in
    aux ()

  let hv_generic_create () =
    let rec loop () =
      match HV_generic.Socket.create () with
      | x -> Lwt.return x
      | exception e ->
        Log.err (fun f -> f "Caught %s while creating hypervisor socket" (Printexc.to_string e));
        Host.Time.sleep_ns (Duration.of_sec 1)
        >>= fun () ->
        loop () in
    loop ()

  let hv_generic_listen uri callback =
    let sockaddr = Hvsock.Socket.sockaddr_of_uri uri in
    Log.info (fun f -> f "Listening on %s" (Hvsock.Socket.string_of_sockaddr sockaddr));
    let rec aux () =
      hv_generic_create ()
      >>= fun socket ->
      Lwt.catch (fun () ->
        HV_generic.Socket.bind socket sockaddr;
        HV_generic.Socket.listen socket 5;
        let rec accept_forever () =
          HV_generic.Socket.accept socket
          >>= fun (t, clientaddr) ->
          Log.info (fun f -> f "Accepted connection from %s" (Hvsock.Socket.string_of_sockaddr clientaddr));
          Lwt.async (fun () -> callback t);
          accept_forever () in
        accept_forever ()
      ) (fun e ->
          Log.warn (fun f -> f "Caught %s while listening on %s"
            (Printexc.to_string e)
            (Hvsock.Socket.string_of_sockaddr sockaddr));
          log_exception_continue "HV_generic.Socket.close" (fun () -> HV_generic.Socket.close socket)
          >>= fun () ->
          Host.Time.sleep_ns (Duration.of_sec 1)
      )
      >>= fun () ->
      aux () in
    aux ()

  let hvsock_connect_forever url sockaddr callback =
    Log.info (fun f -> f "Connecting to %s" (Hvsock.Af_hyperv.string_of_sockaddr sockaddr));
    let rec aux () =
      hvsock_create ()
      >>= fun socket ->
      Lwt.catch (fun () ->
          HV.Socket.connect ~timeout_ms:300 socket sockaddr >>= fun () ->
          Log.info (fun f -> f "AF_HVSOCK connected successfully");
          callback socket
        ) (function
        | Unix.Unix_error(Unix.ETIMEDOUT, _, _) ->
          log_exception_continue "HV.Socket.close" (fun () -> HV.Socket.close socket)
          (* no need to add more delay *)
        | Unix.Unix_error(_, _, _) ->
          log_exception_continue "HV.Socket.close" (fun () -> HV.Socket.close socket)
          >>= fun () ->
          Host.Time.sleep_ns (Duration.of_sec 1)
        | _ ->
          log_exception_continue "HV.Socket.close" (fun () -> HV.Socket.close socket)
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

  let start_server name url flow_cb =
    if url = ""
    then Log.info (fun f ->
        f "No %s server requested. See the --%s argument" name name)
    else Lwt.async (fun () ->
        log_exception_continue
          ("Starting " ^ name ^ " server on: " ^ url)
          (fun () ->
             Log.info (fun f ->
                 f "Starting %s server on: %s" name url);
             unix_listen url
             >>= function
             | Error (`Msg m) ->
               Log.err (fun f -> f "Failed to start %s server because: %s" name m);
               Lwt.return_unit
             | Ok s ->
               Host.Sockets.Stream.Unix.disable_connection_tracking s;
               Host.Sockets.Stream.Unix.listen s flow_cb;
               Lwt.return_unit))

  module type Forwarder = sig
    include Protocol_9p.Filesystem.S
    val make: unit -> t
  end

  (* Create one instance of the Active_list functor per-process. The list of
     current port forwards is stored in a map inside the module (not in the
     `type t` returned from `make`) *)
  let port_forwarder =
      if Sys.os_type = "Unix"
        then (module Active_list.Make(Forward_unix) : Forwarder)
        else (module Active_list.Make(Forward_hvsock) : Forwarder)

  let start_port_forwarding port_control_url max_connections port_forwards =
    (* Figure out where to forward incoming connections to forwarded ports. *)
    let uri = Uri.of_string port_forwards in
    begin match Uri.scheme uri with
    | Some "hyperv-connect" ->
      let sockaddr = hvsock_addr_of_uri ~default_serviceid:ports_serviceid uri in
      Log.info (fun f -> f "Will forward ports over AF_HVSOCK to vpnkit-forwarder on %s"
        (Hvsock.Af_hyperv.string_of_sockaddr sockaddr)
      );
      Connect_hvsock.set_port_forward_addr sockaddr
    | Some "unix" ->
      Connect_unix.vsock_path := Uri.path uri;
      Log.info (fun f -> f "Will forward ports over AF_VSOCK to vpnkit-forwarder on %s" !Connect_unix.vsock_path)
    | None ->
      (* backwards compatible with plain unix path *)
      Connect_unix.vsock_path := port_forwards;
      Log.info (fun f -> f "Will forward ports over AF_VSOCK to vpnkit-forwarder on %s" !Connect_unix.vsock_path)
    | _ ->
      Log.err (fun f -> f "I don't know how to forward ports to %s. Port forwarding will be disabled." port_forwards)
    end;

    (match max_connections with
    | None   -> ()
    | Some _ ->
      Log.warn (fun f ->
          f "The argument max-connections is nolonger supported, use the \
             database key slirp/max-connections instead"));
    Host.Sockets.set_max_connections max_connections;

    Log.info (fun f -> f "Starting port forwarding control 9P server on %s" port_control_url);
    let uri = Uri.of_string port_control_url in
    let module Ports = (val port_forwarder: Forwarder) in
    let fs = Ports.make () in

    match Uri.scheme uri with
    | Some ("hyperv-connect" | "hyperv-listen") ->
      let module Server = Protocol_9p.Server.Make(Log9P)(HV)(Ports) in
      let sockaddr = hvsock_addr_of_uri ~default_serviceid:ports_serviceid uri in
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
    | Some "fd" | None ->
      let module Server =
        Protocol_9p.Server.Make(Log9P)(Host.Sockets.Stream.Unix)(Ports)
      in
      begin unix_listen port_control_url
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
      end
    | _ ->
      let module Server = Protocol_9p.Server.Make(Log9P)(HV_generic)(Ports) in
      let callback fd =
        let flow = HV_generic.connect fd in
        Server.connect fs flow () >>= function
        | Error (`Msg m) ->
          Log.err (fun f -> f "Failed to establish 9P connection: %s" m);
          Lwt.return ()
        | Ok server -> Server.after_disconnect server in
      hv_generic_listen uri callback

  let main_t
      configuration
      socket_url port_control_urls introspection_urls diagnostics_urls pcap_urls
      port_forwards hosts
      listen_backlog gc_compact
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

    Host.start_background_gc gc_compact;

    if hosts <> "" then begin
      match HostsFile.watch ~path:hosts () with
      | Ok _       -> ()
      | Error (`Msg m) ->
        Log.err (fun f -> f "Failed to watch hosts file %s: %s" hosts m);
        ()
    end;

    List.iter
      (fun url ->
        Lwt.async (fun () ->
            log_exception_continue ("Starting the 9P port control filesystem on " ^ url) (fun () ->
                start_port_forwarding url configuration.Configuration.max_connections port_forwards
              )
          )
      ) port_control_urls;

    let vnet_switch = Vnet.create () in

    let uri = Uri.of_string socket_url in

    match Uri.scheme uri with
    | Some ("hyperv-connect"|"hyperv-listen") ->
      let module Slirp_stack =
        Slirp.Make(Vmnet.Make(HV))(Dns_policy)
          (Mclock)(Mirage_random_stdlib)(Vnet)
      in
      let sockaddr =
        hvsock_addr_of_uri ~default_serviceid:ethernet_serviceid
          (Uri.of_string socket_url)
      in
      Slirp_stack.create_static vnet_switch configuration
      >>= fun stack_config ->
      let callback fd =
        let conn = HV.connect fd in
        Slirp_stack.connect stack_config conn >>= fun stack ->
        Log.info (fun f -> f "TCP/IP stack connected");
        List.iter (fun url ->
          start_introspection url (Slirp_stack.filesystem stack)
        ) introspection_urls;
        List.iter (fun url ->
          start_server "diagnostics" url @@ Slirp_stack.diagnostics stack
        ) diagnostics_urls;
        List.iter (fun url ->
          start_server "pcap" url @@ Slirp_stack.pcap stack
        ) pcap_urls;
        Slirp_stack.after_disconnect stack >|= fun () ->
        Log.info (fun f -> f "TCP/IP stack disconnected") in
      if Uri.scheme uri = Some "hyperv-connect"
      then hvsock_connect_forever socket_url sockaddr callback
      else hvsock_listen sockaddr callback
    | Some "fd" | None ->
      let module Slirp_stack =
        Slirp.Make(Vmnet.Make(Host.Sockets.Stream.Unix))(Dns_policy)
          (Mclock)(Mirage_random_stdlib)(Vnet)
      in
      begin unix_listen socket_url
      >>= function
        | Error (`Msg m) ->
          Log.err (fun f -> f "Failed to listen on ethernet socket because: %s" m);
          Lwt.return_unit
        | Ok server ->
        Slirp_stack.create_static vnet_switch configuration
        >>= fun stack_config ->
        Host.Sockets.Stream.Unix.listen server (fun conn ->
            Slirp_stack.connect stack_config conn >>= fun stack ->
            Log.info (fun f -> f "TCP/IP stack connected");
            List.iter (fun url ->
              start_introspection url (Slirp_stack.filesystem stack);
            ) introspection_urls;
            List.iter (fun url ->
              start_server "diagnostics" url @@ Slirp_stack.diagnostics stack
            ) diagnostics_urls;
            List.iter (fun url ->
              start_server "pcap" url @@ Slirp_stack.pcap stack
            ) pcap_urls;
            Slirp_stack.after_disconnect stack >|= fun () ->
            Log.info (fun f -> f "TCP/IP stack disconnected")
          );
        let wait_forever, _ = Lwt.task () in
        wait_forever
      end
    | _ ->
      let module Slirp_stack =
        Slirp.Make(Vmnet.Make(HV_generic))(Dns_policy)
          (Mclock)(Mirage_random_stdlib)(Vnet)
      in
      Slirp_stack.create_static vnet_switch configuration
      >>= fun stack_config ->
      let callback fd =
        let conn = HV_generic.connect fd in
        Slirp_stack.connect stack_config conn >>= fun stack ->
        Log.info (fun f -> f "TCP/IP stack connected");
        List.iter (fun url ->
          start_introspection url (Slirp_stack.filesystem stack)
        ) introspection_urls;
        List.iter (fun url ->
          start_server "diagnostics" url @@ Slirp_stack.diagnostics stack
        ) diagnostics_urls;
        List.iter (fun url ->
          start_server "pcap" url @@ Slirp_stack.pcap stack
        ) pcap_urls;
        Slirp_stack.after_disconnect stack >|= fun () ->
        Log.info (fun f -> f "TCP/IP stack disconnected") in
      hv_generic_listen uri callback

  let main
      socket_url port_control_urls introspection_urls diagnostics_urls pcap_urls pcap_snaplen
      max_connections port_forwards dns http hosts host_names gateway_names
      vm_names listen_backlog port_max_idle_time debug
      server_macaddr domain allowed_bind_addresses gateway_ip host_ip lowest_ip highest_ip
      dhcp_json_path mtu udpv4_forwards tcpv4_forwards gateway_forwards_path gc_compact
    =
    let level =
      let env_debug =
        try ignore @@ Unix.getenv "VPNKIT_DEBUG"; true
        with Not_found -> false
      in
      if debug || env_debug then Some Logs.Debug else Some Logs.Info in
    Logging.setup level;

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
    let parse_forwards protocol forwards =
      List.map (fun x -> match Stringext.split ~on:':' x with
        | [ external_port; internal_ip; internal_port ] ->
          let external_port = int_of_string external_port in
          let internal_ip = Ipaddr.V4.of_string_exn internal_ip in
          let internal_port = int_of_string internal_port in
          Gateway_forwards.( { protocol; external_port; internal_ip; internal_port } )
        | _ ->
          failwith "Failed to parse forwards: expected <local-port>:<remote IP>:<remote port>"
      ) (Stringext.split ~on:',' forwards) in
    let udpv4_forwards = parse_forwards Gateway_forwards.Udp udpv4_forwards in
    let tcpv4_forwards = parse_forwards Gateway_forwards.Tcp tcpv4_forwards in
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
      tcpv4_forwards;
      gateway_forwards_path;
      pcap_snaplen;
    } in
    match socket_url with
      | None ->
        Printf.fprintf stderr "Please provide an --ethernet argument\n"
      | Some socket_url ->
    try
      Host.Main.run
        (main_t configuration socket_url port_control_urls introspection_urls diagnostics_urls pcap_urls
          port_forwards hosts
          listen_backlog gc_compact);
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

let pcap_urls =
  let doc =
    Arg.info ~doc:
      "The address on the host on which to serve a pcap file containing \
        a live stream of all the network traffic on the internal link. \
        Possible values include: \
        /var/tmp/com.docker.slirp.pcap.socket to listen on a Unix domain \
        socket for incoming connections or \
        \\\\\\\\.\\\\pipe\\\\pcap to listen on a Windows named pipe"
      [ "pcap" ]
  in
  Arg.(value & opt_all string [] doc)

let pcap_snaplen =
  let doc =
    Arg.info ~doc:
      "The maximum amount of network packet data to record, see --pcap <address>."
      [ "pcap-snaplen" ]
  in
  Arg.(value & opt int Configuration.default_pcap_snaplen doc)

let max_connections =
  let doc =
    Arg.info ~doc:
      "This argument is deprecated: use the database key slirp/max-connections \
       instead." [ "max-connections" ]
  in
  Arg.(value & opt (some int) None doc)

let port_forwards =
  let doc =
    Arg.info ~doc:
      "Path of the Unix domain socket used to setup virtio-vsock connections \
       to the VM." [ "vsock-path"; "port-forwards" ] ~docv:"VSOCK"
  in
  Arg.(value & opt string "" doc)

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
      "IP address which represents the host. Connections to this IP will be forwarded to localhost on the host. Use the value 0.0.0.0 to disable this feature."
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

let tcpv4_forwards =
  let doc =
    Arg.info ~doc:
      "Configure TCPv4 forwards from the gateway address to remote systems.
       The argument is a comma-separated list of <local port>:<remote IPv4>:<remote port>"
       [ "tcpv4-forwards" ]
  in
  Arg.(value & opt string "" doc)

let gateway_forwards_path =
  let doc =
    Arg.info ~doc:
      "Path of gateway forwards configuration file"
      [ "gateway-forwards" ]
  in
  Arg.(value & opt (some string) None doc)

let gc_compact =
  let doc =
    Arg.info ~doc:
      "Seconds between heap compactions"
      [ "gc-compact-interval" ]
  in
  Arg.(value & opt (some int) None doc)

let command =
  let doc = "proxy TCP/IP connections from an ethernet link via sockets" in
  let man =
    [`S "DESCRIPTION";
     `P "Terminates TCP/IP and UDP/IP connections from a client and proxy the\
         flows via userspace sockets"]
  in
  Term.(pure main
        $ socket $ port_control_urls $ introspection_urls $ diagnostics_urls $ pcap_urls $ pcap_snaplen
        $ max_connections $ port_forwards $ dns $ http $ hosts
        $ host_names $ gateway_names $ vm_names $ listen_backlog $ port_max_idle_time $ debug
        $ server_macaddr $ domain $ allowed_bind_addresses $ gateway_ip $ host_ip
        $ lowest_ip $ highest_ip $ dhcp_json_path $ mtu $ udpv4_forwards $ tcpv4_forwards
        $ gateway_forwards_path $ gc_compact),
  Term.info (Filename.basename Sys.argv.(0)) ~version:Version.git ~doc ~man

let () =
  Printexc.record_backtrace true;

  Lwt.async_exception_hook := (fun exn ->
  Log.err (fun f ->
      f "Lwt.async failure %a: %s" Fmt.exn exn (Printexc.get_backtrace ()))
  );
  Term.exit @@ Term.eval command

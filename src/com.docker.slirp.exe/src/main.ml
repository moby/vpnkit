open Lwt
open Hostnet

let src =
  let src = Logs.Src.create "9P" ~doc:"/port filesystem" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log9P = (val Logs.src_log src : Logs.LOG)

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

let default d = function None -> d | Some x -> x

let ethernet_serviceid = "30D48B34-7D27-4B0B-AAAF-BBBED334DD59"
let ports_serviceid = "0B95756A-9985-48AD-9470-78E060895BE7"

let hvsock_addr_of_uri ~default_serviceid uri =
  (* hyperv://vmid/serviceid *)
  let vmid = match Uri.host uri with None -> Hvsock.Loopback | Some x -> Hvsock.Id x in
  let serviceid =
    let p = Uri.path uri in
    if p = ""
    then default_serviceid
    (* trim leading / *)
    else if String.length p > 0 then String.sub p 1 (String.length p - 1) else p in
    { Hvsock.vmid; serviceid }

module Main(Host: Sig.HOST) = struct

module Connect = Connect.Make(Host)
module Bind = Bind.Make(Host.Sockets)
module Resolv_conf = Resolv_conf.Make(Host.Files)
module Config = Active_config.Make(Host.Time)(Host.Sockets.Stream.Unix)
module Forward = Forward.Make(Connect)(Bind)

module HV = Flow_lwt_hvsock.Make(Host.Time)(Host.Main)

let hvsock_connect_forever url sockaddr callback =
  Log.info (fun f -> f "connecting to %s:%s" (Hvsock.string_of_vmid sockaddr.Hvsock.vmid) sockaddr.Hvsock.serviceid);
  let rec aux () =
    let socket = HV.Hvsock.create () in
    Lwt.catch
      (fun () ->
        HV.Hvsock.connect socket sockaddr
        >>= fun () ->
        Log.info (fun f -> f "hvsock connected successfully");
        callback socket
      ) (function
        | Unix.Unix_error(_, _, _) ->
          HV.Hvsock.close socket
          >>= fun () ->
          Host.Time.sleep 1.
        | _ ->
          HV.Hvsock.close socket
          >>= fun () ->
          Host.Time.sleep 1.
      )
    >>= fun () ->
    aux () in
  Log.debug (fun f -> f "Waiting for connections on socket %s" url);
  aux ()

let start_port_forwarding port_control_url max_connections =
  Log.info (fun f -> f "starting port_forwarding port_control_url:%s max_connections:%s" port_control_url (match max_connections with None -> "None" | Some x -> "Some " ^ (string_of_int x)));
  (* Start the 9P port forwarding server *)
  let module Ports = Active_list.Make(Forward) in
  let module Server = Protocol_9p.Server.Make(Log9P)(HV)(Ports) in
  let fs = Ports.make () in
  Ports.set_context fs "";
  let sockaddr = hvsock_addr_of_uri ~default_serviceid:ports_serviceid (Uri.of_string port_control_url) in
  Connect.set_port_forward_addr sockaddr;
  Connect.set_max_connections max_connections;
  hvsock_connect_forever port_control_url sockaddr
    (fun fd ->
      let flow = HV.connect fd in
      Server.connect fs flow ()
      >>= function
      | Result.Error (`Msg _) ->
        Log.err (fun f -> f "Failed to negotiate 9P connection on port control server");
        HV.Hvsock.close fd
      | Result.Ok t ->
        Log.info (fun f -> f "Client connected to 9P port control server");
        Server.after_disconnect t
        >>= fun () ->
        HV.Hvsock.close fd
    )

module Slirp_stack = Slirp.Make(Config)(Vmnet.Make(HV))(Resolv_conf)(Host)

let main_t socket_url port_control_url max_connections db_path dns pcap debug =
  if debug
  then Logs.set_reporter (Logs_fmt.reporter ())
  else begin
    let h = Eventlog.register "Docker.exe" in
    Logs.set_reporter (Log_eventlog.reporter ~eventlog:h ());
  end;
  Log.info (fun f -> f "vpnkit version %%VERSION%% with hostnet version %s %s uwt version %s hvsock version %s %s"
    Depends.hostnet_version Depends.hostnet_pinned Depends.uwt_version Depends.hvsock_version Depends.hvsock_pinned
  );
  Printexc.record_backtrace true;

  Resolv_conf.set_default_dns [ (Ipaddr.V4 (Ipaddr.V4.of_string_exn dns)), 53 ];

  Lwt.async_exception_hook := (fun exn ->
    Log.err (fun f -> f "Lwt.async failure %s: %s"
      (Printexc.to_string exn)
      (Printexc.get_backtrace ())
    )
  );

  Lwt.async (fun () ->
    log_exception_continue "start_port_server"
      (fun () ->
        start_port_forwarding port_control_url max_connections
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

  let sockaddr = hvsock_addr_of_uri ~default_serviceid:ethernet_serviceid (Uri.of_string socket_url) in
  hvsock_connect_forever socket_url sockaddr
    (fun fd ->
      let conn = HV.connect fd in
      Slirp_stack.connect stack conn
      >>= fun stack ->
      Log.info (fun f -> f "stack connected");
      Slirp_stack.after_disconnect stack
      >>= fun () ->
      Log.info (fun f -> f "stack disconnected");
      Lwt.return ()
    ) >>= fun () ->
  Log.debug (fun f -> f "initialised: serving requests forever");
  let wait_forever, _ = Lwt.task () in
  wait_forever

let main socket_url port_control_url max_connections db_path dns pcap debug =
  Host.Main.run
    (main_t socket_url port_control_url max_connections db_path dns pcap debug)
end

let main socket port_control max_connections db dns pcap select debug =
  let module Use_lwt_unix = Main(Host_lwt_unix) in
  let module Use_uwt = Main(Host_uwt) in
  (if select then Use_lwt_unix.main else Use_uwt.main)
    socket port_control max_connections db dns pcap debug

open Cmdliner

let socket =
  let doc =
    Arg.info ~doc:
      "A URLs to connect to for ethernet of the form \
      hyperv-connect://vmid/serviceid or hyperv-connect://vmid for the default serviceid on Windows \
      or /var/tmp/com.docker.slirp.socket on Mac" ["ethernet"]
  in
  Arg.(value & opt string "" doc)

let port_control_path =
  let doc =
    Arg.info ~doc:
      "A URL to connect to for port control of the form \
     hyperv-connect://vmid/serviceid on Windows or \
     /var/tmp/com.docker.port.socket on Mac" ["port"]
  in
  Arg.(value & opt string "" doc)

let max_connections =
  let doc =
    Arg.info ~doc:
      "Maximum number of concurrent forwarded connections" [ "max-connections" ]
  in
  Arg.(value & opt (some int) None doc)

let db_path =
  let doc =
    Arg.info ~doc:
      "A URLs to connect to datakitof the form \
      file:///var/tmp/foo or tcp://host:port or \\\\\\\\.\\\\pipe\\\\irmin" ["db"]
  in
  Arg.(value & opt (some string) None doc)

let dns =
  let doc =
    Arg.info ~doc:
      "IP address of upstream DNS server" ["dns"]
  in
  Arg.(value & opt string "10.0.75.1" doc)

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
  Term.(pure main $ socket $ port_control_path $ max_connections $ db_path $ dns $ pcap $ select $ debug),
  Term.info (Filename.basename Sys.argv.(0)) ~version:"%%VERSION%%" ~doc ~man

let () =
  Printexc.record_backtrace true;
  match Term.eval command with
  | `Error _ -> exit 1
  | _ -> exit 0

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

let default d = function None -> d | Some x -> x

let ethernet_serviceid = "30D48B34-7D27-4B0B-AAAF-BBBED334DD59"
let ports_serviceid = "0B95756A-9985-48AD-9470-78E060895BE7"

(* These could be shared with datakit. Perhaps they should live in mirage/conduit? *)

let make_unix_socket path =
  Lwt.catch
    (fun () -> Lwt_unix.unlink path)
    (function
      | Unix.Unix_error(Unix.ENOENT, _, _) -> Lwt.return ()
      | e -> Lwt.fail e)
  >>= fun () ->
  let s = Lwt_unix.(socket PF_UNIX SOCK_STREAM 0) in
  Lwt_unix.bind s (Lwt_unix.ADDR_UNIX path);
  Lwt.return s

let unix_accept_forever url socket callback =
  Lwt_unix.listen socket 5;
  let rec aux () =
    Lwt_unix.accept socket >>= fun (client, _addr) ->
    let _ = (* background thread *)
      (* the callback will close the connection when its done *)
      callback client in
    aux () in
  Log.debug (fun l -> l "Waiting for connections on socket %S" url);
  aux ()

let rec named_pipe_accept_forever path callback =
  let open Lwt.Infix in
  let p = Named_pipe_lwt.Server.create path in
  Named_pipe_lwt.Server.connect p
  >>= function
  | false ->
    Log.err (fun f -> f "Named-pipe connection failed on %s" path);
    Lwt.return ()
  | true ->
    let _ = (* background thread *)
      let fd = Named_pipe_lwt.Server.to_fd p in
      callback fd in
    named_pipe_accept_forever path callback

let hvsock_connect_forever url sockaddr callback =
  Log.info (fun f -> f "connecting to %s:%s" (Hvsock.string_of_vmid sockaddr.Hvsock.vmid) sockaddr.Hvsock.serviceid);
  let rec aux () =
    let socket = Lwt_hvsock.create () in
    Lwt.catch
      (fun () ->
        Lwt_hvsock.connect socket sockaddr
        >>= fun () ->
        Log.info (fun f -> f "hvsock connected successfully");
        callback socket
      ) (function
        | Unix.Unix_error(_, _, _) ->
          Lwt_hvsock.close socket
          >>= fun () ->
          Lwt_unix.sleep 1.
        | _ ->
          Lwt_hvsock.close socket
          >>= fun () ->
          Lwt_unix.sleep 1.
      )
    >>= fun () ->
    aux () in
  Log.debug (fun f -> f "Waiting for connections on socket %s" url);
  aux ()

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

let accept_forever urls callback =
  Lwt_list.iter_p (fun url ->
    Lwt.catch
      (fun () ->
         (* Check if it looks like a UNC name before a URI *)
         let is_unc =
           String.length url > 2 && String.sub url 0 2 = "\\\\" in
         if is_unc
         then named_pipe_accept_forever url callback
         else
         let uri = Uri.of_string url in
         match Uri.scheme uri with
         | Some "file" ->
           make_unix_socket (Uri.path uri)
           >>= fun socket ->
           unix_accept_forever url socket callback
         | Some "tcp" ->
           let host = Uri.host uri |> default "127.0.0.1" in
           let port = Uri.port uri |> default 5640 in
           let addr = Lwt_unix.ADDR_INET (Unix.inet_addr_of_string host, port) in
           let socket = Lwt_unix.(socket PF_INET SOCK_STREAM 0) in
           Lwt_unix.bind socket addr;
           unix_accept_forever url socket callback
         | _ ->
           Printf.fprintf stderr
             "Unknown URL schema. Please use file: or tcp:\n";
           exit 1
      )
      (fun ex ->
         Printf.fprintf stderr
           "Failed to set up server socket listening on %S: %s\n%!"
           url (Printexc.to_string ex);
         exit 1
      )
  ) urls

module Forward = Forward.Make(Connect)(Bind)

let start_port_forwarding port_control_url =
  Log.info (fun f -> f "starting port_forwarding port_control_url:%s" port_control_url);
  (* Start the 9P port forwarding server *)
  let module Ports = Active_list.Make(Forward) in
  let module Server = Protocol_9p.Server.Make(Log)(Flow_lwt_hvsock)(Ports) in
  let fs = Ports.make () in
  Socket_stack.connect ()
  >>= function
  | `Error (`Msg m) ->
    Log.err (fun f -> f "Failed to create a socket stack: %s" m);
    exit 1
  | `Ok _ ->
  Ports.set_context fs "";
  let sockaddr = hvsock_addr_of_uri ~default_serviceid:ports_serviceid (Uri.of_string port_control_url) in
  Connect.set_port_forward_addr sockaddr;
  hvsock_connect_forever port_control_url sockaddr
    (fun fd ->
      let flow = Flow_lwt_hvsock.connect fd in
      Server.connect fs flow ()
      >>= function
      | Result.Error (`Msg _) ->
        Log.err (fun f -> f "Failed to negotiate 9P connection on port control server");
        Lwt_hvsock.close fd
      | Result.Ok t ->
        Log.info (fun f -> f "Client connected to 9P port control server");
        Server.after_disconnect t
        >>= fun () ->
        Lwt_hvsock.close fd
    )

module Slirp_stack = Slirp.Make(Vmnet.Make(Flow_lwt_hvsock))(Resolv_conf)

let main_t socket_url port_control_url db_path dns pcap debug =
  if debug
  then Logs.set_reporter (Logs_fmt.reporter ())
  else begin
    let h = Eventlog.register "Docker.exe" in
    Logs.set_reporter (Log_eventlog.reporter ~eventlog:h ());
  end;
  Printexc.record_backtrace true;

  Resolv_conf.set_dns dns;

  Lwt.async_exception_hook := (fun exn ->
    Log.err (fun f -> f "Lwt.async failure %s: %s"
      (Printexc.to_string exn)
      (Printexc.get_backtrace ())
    )
  );

  Lwt.async (fun () ->
    log_exception_continue "start_port_server"
      (fun () ->
        start_port_forwarding port_control_url
      )
    );

  ( match db_path with
    | Some db_path ->
      let db = Active_config.create "named-pipe" db_path in
      Slirp_stack.create db
    | None ->
      Log.warn (fun f -> f "no database: using hardcoded network configuration values");
      let never, _ = Lwt.task () in
      let pcap = match pcap with None -> None | Some filename -> Some (filename, None) in
      Lwt.return { Slirp_stack.peer_ip = Ipaddr.V4.of_string_exn "192.168.65.2";
        local_ip = Ipaddr.V4.of_string_exn "192.168.65.1";
        pcap_settings = Active_config.Value(pcap, never) }
  ) >>= fun stack ->

  let sockaddr = hvsock_addr_of_uri ~default_serviceid:ethernet_serviceid (Uri.of_string socket_url) in
  hvsock_connect_forever socket_url sockaddr
    (fun fd ->
      let conn = Flow_lwt_hvsock.connect fd in
      Slirp_stack.connect stack conn
    )

let main socket port_control db dns pcap debug =
  Lwt_main.run @@ main_t socket port_control db dns pcap debug

open Cmdliner

let socket =
  let doc =
    Arg.info ~doc:
      "A URLs to connect to for ethernet of the form \
      hyperv-connect://vmid/serviceid or hyperv-connect://vmid for the default serviceid" ["ethernet"]
  in
  Arg.(value & opt string "hyperv-connect://vmid/serviceid" doc)

let port_control_path =
  let doc =
    Arg.info ~doc:
      "A URL to connect to for port control of the form \
      hyperv-connect://vmid/serviceid" ["port"]
  in
  Arg.(value & opt string "hyperv-connect://vmid/serviceid" doc)

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
  Term.(pure main $ socket $ port_control_path $ db_path $ dns $ pcap $ debug),
  Term.info "proxy" ~doc ~man

let () =
  Printexc.record_backtrace true;
  match Term.eval command with
  | `Error _ -> exit 1
  | _ -> exit 0

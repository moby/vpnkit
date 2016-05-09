(*
 * Copyright (C) 2016 David Scott <dave.scott@docker.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)
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

let start_port_forwarding port_control_urls =
  Log.info (fun f -> f "starting port_forwarding port_control_urls:%s"
    (String.concat ", " port_control_urls)
  );
  (* Start the 9P port forwarding server *)
  let module Ports = Active_list.Make(Forward) in
  let module Server = Protocol_9p.Server.Make(Log)(Flow_lwt_unix)(Ports) in
  let fs = Ports.make () in
  Socket_stack.connect ()
  >>= function
  | `Error (`Msg m) ->
    Log.err (fun f -> f "Failed to create a socket stack: %s" m);
    exit 1
  | `Ok s ->
  Ports.set_context fs "";
  accept_forever port_control_urls
    (fun fd ->
      let flow = Flow_lwt_unix.connect fd in
      Server.connect fs flow ()
      >>= function
      | Result.Error (`Msg x) ->
        Log.err (fun f -> f "Failed to negotiate 9P connection on port control server");
        Lwt_unix.close fd
      | Result.Ok t ->
        Log.info (fun f -> f "Client connected to 9P port control server");
        Server.after_disconnect t
        >>= fun () ->
        Lwt_unix.close fd
    )

module Slirp_stack = Slirp.Make(Vmnet)(Resolv_conf)

let main_t socket_urls port_control_urls db_path debug =
  if debug
  then Logs.set_reporter (Logs_fmt.reporter ())
  else begin
    let h = Eventlog.register "Docker.exe" in
    Logs.set_reporter (Log_eventlog.reporter h ());
  end;
  Log.info (fun f -> f "Setting handler to ignore all SIGPIPE signals");
  Sys.set_signal Sys.sigpipe Sys.Signal_ignore;
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
        start_port_forwarding port_control_urls
      )
    );

  let config = Active_config.create "named-pipe" db_path in
  Slirp_stack.create config
  >>= fun stack ->
  accept_forever socket_urls
    (fun fd ->
      Slirp_stack.connect stack fd
    )

let main socket port_control db debug =
  Lwt_main.run @@ main_t socket port_control db debug

open Cmdliner

let socket =
  let doc =
    Arg.info ~doc:
      "A comma-separated list of URLs to listen on for ethernet of the form \
      file:///var/tmp/foo or tcp://host:port or \\\\\\\\.\\\\pipe\\\\foo" ["url"]
  in
  Arg.(value & opt (list string) [ "\\\\\\\\.\\\\pipe\\\\slirp" ] doc)

let port_control_path =
  let doc =
    Arg.info ~doc:
      "A comma-separated list of URLs to listen on for port control of the form \
      file:///var/tmp/foo or tcp://host:port or \\\\\\\\.\\\\pipe\\\\foo" ["url"]
  in
  Arg.(value & opt (list string) [ "\\\\\\\\.\\\\pipe\\\\port" ] doc)

let db_path =
  let doc =
    Arg.info ~doc:
      "A URLs to connect to datakitof the form \
      file:///var/tmp/foo or tcp://host:port or \\\\\\\\.\\\\pipe\\\\foo" ["url"]
  in
  Arg.(value & opt string "\\\\\\\\.\\\\pipe\\\\datakit" doc)

let debug =
  let doc = "Verbose debug logging to stdout" in
  Arg.(value & flag & info [ "debug" ] ~doc)

let command =
  let doc = "proxy TCP/IP connections from an ethernet link via sockets" in
  let man =
    [`S "DESCRIPTION";
     `P "Terminates TCP/IP and UDP/IP connections from a client and proxy the
		     flows via userspace sockets"]
  in
  Term.(pure main $ socket $ port_control_path $ db_path $ debug),
  Term.info "proxy" ~doc ~man

let () =
  Printexc.record_backtrace true;
  match Term.eval command with
  | `Error _ -> exit 1
  | _ -> exit 0

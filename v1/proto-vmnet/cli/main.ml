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

let src =
  let src = Logs.Src.create "vmnet" ~doc:"vmnet CLI" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let or_failwith = function
  | `Error (`Msg x) -> failwith x
  | `Ok x -> x

let connect_client socket debug =
  let s = Lwt_unix.socket Lwt_unix.PF_UNIX Lwt_unix.SOCK_STREAM 0 in
  Lwt_unix.connect s (Unix.ADDR_UNIX socket)
  >>= fun () ->
  Vmnet_client.of_fd s
  >>= fun r ->
  let c = or_failwith r in
  Lwt.return c

let bind_main_t socket ip port stream debug =
  let ip = Ipaddr.V4.of_string_exn ip in
  connect_client socket debug
  >>= fun c ->
  Vmnet_client.bind_ipv4 c (ip, port, stream)
  >>= fun r ->
  let fd = or_failwith r in
  Log.debug (fun f -> f "Received fd successfully");
  Lwt_unix.listen fd 5;
  Lwt_unix.accept fd
  >>= fun (client, _) ->
  Log.debug (fun f -> f "Connected to client");
  Lwt_unix.write client "hello\n" 0 6
  >>= fun _ ->
  Lwt_unix.close fd

let bind_main socket ip port stream debug = Lwt_main.run @@ bind_main_t socket ip port stream debug

open Cmdliner

let socket =
  Arg.(value & opt string "/var/tmp/com.docker.vmnetd.socket" & info [ "socket" ] ~docv:"SOCKET")

let ip =
  Arg.(value & opt string "0.0.0.0" & info [ "ip" ] ~docv:"IP")

let port =
  Arg.(value & opt int 80 & info [ "port" ] ~docv:"PORT")

let stream =
  let doc = "Bind a SOCK_STREAM, else a SOCK_DGRAM" in
  Arg.(value & flag & info [ "stream" ] ~doc)

let debug =
  let doc = "Verbose debug logging to stdout" in
  Arg.(value & flag & info [ "debug" ] ~doc)

let bind_cmd =
  let doc = "talk to vmnetd" in
  let man =
    [`S "DESCRIPTION";
     `P "Ask vmnetd to bind a socket"]
  in
  Term.(pure bind_main $ socket $ ip $ port $ stream $ debug),
  Term.info "bind" ~doc ~man

let help = [
 `S "MORE HELP";
 `P "Use `$(mname) $(i,COMMAND) --help' for help on a single command."; `Noblank;
 `S "BUGS"; `P (Printf.sprintf "Check bug reports at docker/pinata");
]

let default_cmd =
  let doc = "Sends simple commands to vmnetd" in
  let man = help in
  Term.(ret (pure (`Help (`Pager, None)))),
  Term.info "vmnet-cli" ~version:"0.1" ~doc ~man

let () =
  Printexc.record_backtrace true;
  match Term.eval_choice default_cmd [ bind_cmd ] with
  | `Error _ -> exit 1
  | _ -> exit 0

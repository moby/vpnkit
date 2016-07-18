open Lwt.Infix
open Astring

module Time = struct
  type 'a io = 'a Lwt.t
  let sleep = Lwt_unix.sleep
end
module AC = Active_config.Make(Time)(Flow_lwt_unix)

let open_tcp hostname port =
  Lwt_unix.gethostbyname hostname
  >>= fun h ->
  (* This should probably be a Result error and not an Lwt error. *)
  ( if Array.length h.Lwt_unix.h_addr_list = 0
    then
      let msg =
        Printf.sprintf "gethostbyname returned 0 addresses for '%s'" hostname
      in
      Lwt.fail (Failure msg)
    else Lwt.return h.Lwt_unix.h_addr_list.(0)
  ) >>= fun inet_addr ->
  let s = Lwt_unix.socket h.Lwt_unix.h_addrtype Lwt_unix.SOCK_STREAM 0 in
  Lwt_unix.connect s (Lwt_unix.ADDR_INET (inet_addr, port))
  >>= fun () ->
  Lwt.return s

let open_unix path =
  let s = Lwt_unix.socket Lwt_unix.PF_UNIX Lwt_unix.SOCK_STREAM 0 in
  Lwt_unix.connect s (Lwt_unix.ADDR_UNIX path)
  >>= fun () ->
  Lwt.return s

let connect proto address () =
  ( match proto, address with
    | "tcp", _ ->
      begin match String.cuts ~sep:":" address with
        | [ hostname; port ] -> open_tcp hostname (int_of_string port)
        | [ hostname ]       -> open_tcp hostname 5640
        | _ ->
          Lwt.fail_with (Printf.sprintf "Unable to parse %s %s" proto address)
      end
    | "unix", _ ->
      open_unix address
    | _, address when String.is_prefix ~affix:"\\\\" address ->
      Named_pipe_lwt.Client.openpipe address
      >>= fun pipe ->
      Lwt.return (Named_pipe_lwt.Client.to_fd pipe)
    | _ ->
      Lwt.fail_with (Printf.sprintf "Unknown protocol %s" proto)
  ) >>= fun s ->
  Lwt.return (Result.Ok (Flow_lwt_unix.connect s))

let watch address key =
  let proto, address = match String.cut ~sep:":" address with
    | Some (proto, address) -> proto, address
    | None -> failwith "Failed to parse protocol:address" in
  let path = String.cuts ~sep:"/" key in
  let t =
    let reconnect = connect proto address in
    let config = AC.create ~reconnect () in
    AC.string_option config path
    >>= fun string_options ->
    let rec loop string_options =
      Printf.printf "%s\n%!" (match Active_config.hd string_options with None -> "None" | Some x -> "Some " ^ x);
      Active_config.tl string_options
      >>= fun remaining ->
      loop remaining in
    loop string_options in
  try
    Lwt_main.run (t >|= fun () -> `Ok ())
  with e ->
    Printf.fprintf stderr "Caught: %s\n%!" (Printexc.to_string e);
    `Error(false, Printexc.to_string e)

open Cmdliner

let address =
  Arg.(value & opt string "unix:/var/tmp/com.docker.db.socket" & info [ "a"; "address" ] ~docv:"ADDRESS")

let key =
  Arg.(value & pos 0 string "com.docker.driver.amd64-linux/native/port-forwarding" & info [] ~docv:"KEY")

let command =
  let doc = "watch the database for specific key changes" in
  let man =
    [`S "DESCRIPTION";
     `P "Watch the database for specific key changes" ]
  in
  Term.(pure watch $ address $ key),
  Term.info "watch" ~doc ~man

let () =
  Printexc.record_backtrace true;
  Logs.set_reporter (Logs_fmt.reporter ());
  match Term.eval command with
  | `Error _ -> exit 1
  | _ -> exit 0

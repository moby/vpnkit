open Lwt.Infix

let watch address key =
  let proto, address = match Stringext.split ~on:':' ~max:2 address with
    | [ proto; address ] -> proto, address
    | _ -> failwith "Failed to parse protocol:address" in
  let path = Stringext.split ~on:'/' key in
  let t =
    let config = Active_config.create proto address in
    Active_config.string_option config path
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

let src =
  let src = Logs.Src.create "logging" ~doc:"logging control" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let asl_install () =
  let facility = Filename.basename Sys.executable_name in
  let client = Asl.Client.create ~ident:"Docker" ~facility () in
  Logs.set_reporter (Log_asl.reporter ~client ());
  (* Replace stdout and stderr with /dev/null to avoid 2 overlapping logging
     streams (possibly leading to corruption if the App writes to the same
     file) *)
  let dev_null = Unix.openfile "/dev/null" [ Unix.O_WRONLY ] 0 in
  Unix.dup2 dev_null Unix.stdout;
  Unix.dup2 dev_null Unix.stderr;
  Log.debug (fun f -> f "stdout and stderr have been redirected to /dev/null")

let install ~stdout =
  (* Write to stdout if expicitly requested [debug = true] or if the environment
     variable DEBUG is set *)
  let env_debug = try ignore @@ Unix.getenv "DEBUG"; true with Not_found -> false in
  if stdout || env_debug then begin
    Logs.set_reporter (Logs_fmt.reporter ());
    Log.info (fun f -> f "Logging to stdout (stdout:%b DEBUG:%b)" stdout env_debug);
  end else begin
    asl_install ();
    Log.info (fun f -> f "Logging to Apple System Log")
  end

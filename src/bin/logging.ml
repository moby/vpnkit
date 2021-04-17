(* Based on https://github.com/moby/datakit/blob/master/src/datakit-log/datakit_log.ml *)

type t =
  | Quiet
  | Eventlog
  | ASL

open Cmdliner

let mk = Arg.enum [
    "quiet"    , Quiet;
    "eventlog" , Eventlog;
    "asl"      , ASL;
  ]

  let pp_ptime f () =
    let open Unix in
    let tm = Unix.gmtime (Unix.time ()) in
    Fmt.pf f "time=\"%04d-%02d-%02dT%02d:%02d:%02dZ\"" (tm.tm_year + 1900) (tm.tm_mon + 1)
      tm.tm_mday tm.tm_hour tm.tm_min tm.tm_sec

let reporter =
  let report src level ~over k msgf =
    let k _ =
      over ();
      k ()
    in
    let src = Logs.Src.name src in
    let with_stamp _h _tags k fmt =
      let level = Logs.level_to_string (Some level) in

      Fmt.kpf k Fmt.stderr
        ("\r%a level=%a @[msg=\"%a: " ^^ fmt ^^ "\"@]@.")
        pp_ptime ()
        Fmt.string level
        Fmt.string src

    in
    msgf @@ fun ?header ?tags fmt ->
    with_stamp header tags k fmt
  in
  { Logs.report }

let setup log_destination level =
  Logs.set_level level;
  match log_destination with
  | Quiet    -> Logs.set_reporter (reporter)
  | Eventlog ->
    let eventlog = Eventlog.register "Docker.exe" in
    Logs.set_reporter (Log_eventlog.reporter ~eventlog ())
  | ASL ->
    let facility = Filename.basename Sys.executable_name in
    let client = Asl.Client.create ~ident:"Docker" ~facility () in
    Logs.set_reporter (Log_asl.reporter ~client ())

let docs = "LOG OPTIONS"

let log_destination =
  let doc =
    Arg.info ~docs ~doc:"Destination for the logs" [ "log-destination" ]
  in
  Arg.(value & opt mk Quiet & doc)
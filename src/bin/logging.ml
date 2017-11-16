(* Based on https://github.com/moby/datakit/blob/master/src/datakit-log/datakit_log.ml *)

type t =
  | Quiet
  | Eventlog
  | ASL

open Cmdliner

let mk = Arg.enum [
    "quiet"    , Quiet;
    "eventlog" , Eventlog;
    "asl"      , ASL
  ]

let setup log_destination level =
  Logs.set_level level;
  match log_destination with
  | Quiet    -> Logs.set_reporter (Logs_fmt.reporter ())
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
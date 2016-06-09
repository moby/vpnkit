val install: stdout:bool -> unit
(** [install stdout] installs a log reporter. If stdout is true, then logs
    are sent only to stdout, otherwise logs are sent to ASL *)

(* Based on https://github.com/moby/datakit/blob/master/src/datakit-log/datakit_log.ml *)

  let pp_ptime f () =
    let open Unix in
    let s = Unix.gettimeofday () in
    let tm = Unix.gmtime s in
    let nsecs = Float.rem s Float.one *. 1e9 |> int_of_float in
    Fmt.pf f "%04d-%02d-%02dT%02d:%02d:%02d.%09dZ" (tm.tm_year + 1900) (tm.tm_mon + 1)
      tm.tm_mday tm.tm_hour tm.tm_min tm.tm_sec nsecs

let process = Filename.basename Sys.argv.(0)

let with_lock m f x =
  Mutex.lock m;
  try
    let result = f x in
    Mutex.unlock m;
    result
  with e ->
    Mutex.unlock m;
    raise e

let reporter =
  let buffer = Buffer.create 1024 in
  let m = Mutex.create () in
  let c = Condition.create () in
  let (_: Thread.t) = Thread.create (fun () ->
    let rec next () = match Buffer.contents buffer with
      | "" ->
        Condition.wait c m;
        next ()
      | data ->
        Buffer.reset buffer;
        data in
    let rec loop () =
      let data = with_lock m next () in
      (* Block writing to stderr without the buffer mutex held. Logging may continue into the buffer. *)
      output_string stderr data;
      flush stderr;
      loop () in
    loop ()
  ) () in
  let buffer_fmt = Format.formatter_of_buffer buffer in


  let report src level ~over k msgf =
    let k _ =
      Condition.signal c;
      over ();
      k ()
    in
    let src = Logs.Src.name src in
    msgf @@ fun ?header ?tags fmt ->
      let level = Logs.level_to_string (Some level) in
      with_lock m
        (fun () ->
          Format.kfprintf k buffer_fmt
            ("[%a][%a][%a] %a: " ^^ fmt ^^ "@.")
            pp_ptime ()
            Fmt.string process
            Fmt.string level
            Fmt.string src
        ) ()
  in
  { Logs.report }

let setup level =
  Logs.set_level level;
  Logs.set_reporter reporter

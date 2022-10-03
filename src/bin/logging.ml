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

let buffer = Buffer.create 128
let m = Mutex.create ()
let c = Condition.create ()
let shutdown_requested = ref false
let shutdown_done = ref false

let shutdown () =
  with_lock m
    (fun () ->
      shutdown_requested := true;
      Buffer.add_string buffer "logging system has shutdown";
      Condition.broadcast c;
      while not !shutdown_done do
        Condition.wait c m;
      done
    ) ()

let reporter =
  let max_buffer_size = 65536 in
  let dropped_bytes = ref 0 in
  let (_: Thread.t) = Thread.create (fun () ->
    let rec next () = match Buffer.contents buffer with
      | "" ->
        Condition.wait c m;
        next ()
      | data ->
        let dropped = !dropped_bytes in
        dropped_bytes := 0;
        Buffer.reset buffer;
        data, dropped in
    let should_continue () = match Buffer.contents buffer with
      | "" ->
        if !shutdown_requested then begin
          shutdown_done := true;
          Condition.broadcast c;
        end;
        not !shutdown_done
      | _ -> true (* more logs to print *) in
    let rec loop () =
      let data, dropped = with_lock m next () in
      (* Block writing to stderr without the buffer mutex held. Logging may continue into the buffer. *)
      output_string stderr data;
      if dropped > 0 then begin
        output_string stderr (Printf.sprintf "%d bytes of logs dropped\n" dropped)
      end;
      flush stderr;
      if with_lock m should_continue () then loop () in
    loop ()
  ) () in
  let buffer_fmt = Format.formatter_of_buffer buffer in


  let report src level ~over k msgf =
    let k _ =
      Condition.broadcast c;
      over ();
      k ()
    in
    let src = Logs.Src.name src in
    msgf @@ fun ?header:_ ?tags:_ fmt ->
      let level = Logs.level_to_string (Some level) in
      with_lock m
        (fun () ->
          let destination =
            if Buffer.length buffer > max_buffer_size then begin
              Format.make_formatter (fun _ _ _ -> ()) (fun () -> ())
            end else buffer_fmt in
          Format.kfprintf k destination
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

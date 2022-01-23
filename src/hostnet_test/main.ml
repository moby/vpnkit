let src =
  let src = Logs.Src.create "test" ~doc:"Test the slirp stack" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let ppf, flush =
  let b = Buffer.create 255 in
  let flush () = let s = Buffer.contents b in Buffer.clear b; s in
  Format.formatter_of_buffer b, flush

let reporter =
  let start = Unix.gettimeofday () in
  fun () ->
    let report _src level ~over k msgf =
      let k _ = Printf.printf "%s%!" (flush ()); over (); k () in
      msgf @@ fun ?header:_ ?tags:_ fmt ->
      let t = Unix.gettimeofday () -. start in
      Format.kfprintf k ppf ("%.5f [%a] @[" ^^ fmt ^^ "@]@.") t Logs.pp_level level in
    { Logs.report }

(* Run it *)
let () =
  Logs.set_reporter (reporter ());
  Lwt.async_exception_hook := (fun exn ->
      Log.err (fun f -> f "Lwt.async failure %s: %s"
                  (Printexc.to_string exn)
                  (Printexc.get_backtrace ())
              )
    );

  (* One test requires 1026 descriptors on Unix so run ourself with the ulimit *)
  let child_arg = "--child" in
  let is_child = Array.length Sys.argv = 2 && Sys.argv.(1) = child_arg in
  if Sys.os_type = "Unix" && not is_child then begin
    match Unix.system (Printf.sprintf "ulimit -n 1500 && %s --child" Sys.argv.(0)) with
    | Unix.WEXITED n -> exit n
    | _ ->
      Printf.fprintf stderr "unable to re-run with ulimit\n";
      exit 1
  end;

  Host.start_background_gc None;

  List.iter
    (fun (test, cases) ->
       Printf.fprintf stderr "\n**** Starting test %s\n%!" test;
       List.iter (fun (case, _, fn) ->
           Printf.fprintf stderr "Starting test case %s\n%!" case;
           fn ()
         ) cases
    ) (Suite.tests @ Suite.scalability)

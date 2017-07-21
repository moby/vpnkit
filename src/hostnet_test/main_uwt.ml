let src =
  let src = Logs.Src.create "test" ~doc:"Test the slirp stack" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Tests = Suite.Make(Host_uwt)

(* Run it *)
let () =
  Logs.set_reporter (Logs_fmt.reporter ());
  Lwt.async_exception_hook := (fun exn ->
      Log.err (fun f -> f "Lwt.async failure %s: %s"
                  (Printexc.to_string exn)
                  (Printexc.get_backtrace ())
              )
    );
  List.iter
    (fun (test, cases) ->
       Printf.fprintf stderr "\n**** Starting test %s\n%!" test;
       List.iter (fun (case, _, fn) ->
           Printf.fprintf stderr "Starting test case %s\n%!" case;
           fn ()
         ) cases
    ) (Tests.tests @ Tests.scalability)

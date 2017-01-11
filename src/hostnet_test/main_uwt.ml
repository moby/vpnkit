open Hostnet
open Lwt.Infix

let src =
  let src = Logs.Src.create "test" ~doc:"Test the slirp stack" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Tests = Suite.Make(Host_uwt)

let tests =
  (List.map (fun (name, test) -> name ^ "_with_Uwt", test) Tests.suite) @
  Hosts_test.suite

(* Run it *)
let () =
  Logs.set_reporter (Logs_fmt.reporter ());
  Lwt.async_exception_hook := (fun exn ->
    Log.err (fun f -> f "Lwt.async failure %s: %s"
      (Printexc.to_string exn)
      (Printexc.get_backtrace ())
    )
  );
  Alcotest.run "Hostnet" tests

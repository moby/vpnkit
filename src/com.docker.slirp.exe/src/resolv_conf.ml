let src =
  let src = Logs.Src.create "port forward" ~doc:"forward local ports to the VM" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let upstream_dns = ref (Ipaddr.V4.of_string_exn "127.0.0.1")

let set_dns dns =
  Log.info (fun f -> f "using DNS forwarder on %s:53" dns);
  upstream_dns := (Ipaddr.V4.of_string_exn dns)

let get () =
  Lwt.return [ Ipaddr.V4 !upstream_dns, 53 ]

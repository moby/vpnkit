let src =
  let src = Logs.Src.create "port forward" ~doc:"forward local ports to the VM" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let default_dns = ref [ Ipaddr.V4 (Ipaddr.V4.of_string_exn "127.0.0.1"), 53 ]

let set_default_dns dns = default_dns := dns

let current_dns = ref !default_dns

let set = function
  | _ :: _ as dns ->
    Log.info (fun f -> f "using DNS forwarders on %s"
      (String.concat "; " (List.map (fun (ip, port) -> Ipaddr.to_string ip ^ "#" ^ (string_of_int port)) dns))
    );
    current_dns := dns
  | [] ->
    Log.info (fun f -> f "using default DNS on %s"
      (String.concat "; " (List.map (fun (ip, port) -> Ipaddr.to_string ip ^ "#" ^ (string_of_int port)) !default_dns))
    );
    current_dns := !default_dns

let get () =
  Lwt.return !current_dns

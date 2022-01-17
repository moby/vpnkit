open Lwt.Infix
open Slirp_stack

let src =
  let src = Logs.Src.create "test" ~doc:"Test the slirp stack" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let failf fmt = Fmt.kstr failwith fmt

let run_test ?(timeout=Duration.of_sec 60) t =
  let timeout =
    Host.Time.sleep_ns timeout >>= fun () ->
    Lwt.fail_with "timeout"
  in
  Host.Main.run @@ Lwt.pick [ timeout; t ]

let run ?timeout ~pcap t = run_test ?timeout (with_stack ~pcap t)

let test_nmap () =
  (* Attempt to connect to all ports on the host IP, then see if the host
     is still pingable afterwards. This checks for connection leaks / exchaustion. *)

  let t _ stack =
    let start = Unix.gettimeofday () in
    let open_ports = ref [] in
    let connect_disconnect ip port =
      Client.TCPV4.create_connection (Client.tcpv4 stack.Client.t) (ip, port)
      >>= function
      | Error _ ->
        Lwt.return_unit
      | Ok flow ->
        open_ports := port :: !open_ports;
        Client.TCPV4.close flow
        >>= fun () ->
        Lwt.return_unit in
    (* Limit the number of concurrent connection requests *)
    let max_concurrent = 10000 in
    let cur_concurrent = ref 0 in
    let completed = ref 0 in
    let cur_concurrent_c = Lwt_condition.create () in
    let rec scan_all_ports ip first last =
      if first > last
      then Lwt.return_unit
      else begin
        let rec wait () =
          if !cur_concurrent < max_concurrent then begin
            incr cur_concurrent;
            Lwt.return_unit
          end else begin
            Lwt_condition.wait cur_concurrent_c
            >>= fun () ->
            wait ()
          end in
        wait ()
        >>= fun () ->
        Lwt.async (fun () ->
          connect_disconnect ip first
          >>= fun () ->
          decr cur_concurrent;
          incr completed;
          Lwt_condition.broadcast cur_concurrent_c ();
          Lwt.return_unit
        );
        scan_all_ports ip (first + 1) last
      end in
    let rec show_status () =
      Host.Time.sleep_ns (Duration.of_sec 5)
      >>= fun () ->
      Log.info (fun f -> f "Connections completed: %d; connections in progress: %d" !completed !cur_concurrent);
      show_status () in
    Lwt.pick [
      scan_all_ports localhost_ip 1 65535;
      show_status ()
    ] >>= fun () ->
    let rec wait () =
      if !cur_concurrent > 0 then begin
        Lwt_condition.wait cur_concurrent_c
        >>= fun () ->
        wait ()
      end else Lwt.return_unit in
    wait ()
    >>= fun () ->
    Log.info (fun f -> f "Total time taken to scan localhost: %.1f seconds" (Unix.gettimeofday () -. start));
    Log.info (fun f -> f "The following ports are open:");
    List.iter (fun port -> Log.info (fun f -> f "  %d" port)) !open_ports;
    (* Ping the host to check it's still working *)
    let rec loop seq =
      if Queue.length Client.Icmpv41.packets > 0
      then Lwt.return_unit
      else begin
        let ping = Packets.icmp_echo_request ~id:0x1234 ~seq ~len:0 in
        Log.info (fun f -> f "sending ping to verify the stack is still working");
        Client.Icmpv41.write stack.Client.icmpv4 ~dst:localhost_ip ping
        >>= function
        | Error e -> failf "Icmpv41.write failed: %a" Client.Icmpv41.pp_error e
        | Ok () ->
          Host.Time.sleep_ns (Duration.of_sec 1)
          >>= fun () ->
          loop (seq + 1)
      end in
    Queue.clear Client.Icmpv41.packets;
    loop 0
  in
  run ~timeout:(Duration.of_sec 900) ~pcap:"nmap.pcap" t
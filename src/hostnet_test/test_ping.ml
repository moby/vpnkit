open Lwt.Infix

let src =
  let src = Logs.Src.create "tcp" ~doc:"Test ICMP ping" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

let failf fmt = Fmt.kstr failwith fmt

module Log = (val Logs.src_log src : Logs.LOG)

let google_1 = Ipaddr.V4.of_string_exn "8.8.8.8"
let google_2 = Ipaddr.V4.of_string_exn "8.8.4.4"

let test_ping () =
  let id = 0x1234 in
  Queue.clear Slirp_stack.Client.Icmpv41.packets;
  Host.Main.run begin
    Slirp_stack.with_stack ~pcap:"test_ping.pcap" (fun _ stack ->
      let rec loop seq =
        if Queue.length Slirp_stack.Client.Icmpv41.packets > 0
        then Lwt.return_unit
        else begin
          let ping = Packets.icmp_echo_request ~id ~seq ~len:0 in
          Printf.printf "sending ping\n%!";
          Slirp_stack.Client.Icmpv41.write stack.Slirp_stack.Client.icmpv4 ~dst:google_1 ping
          >>= function
          | Error e -> failf "Icmpv41.write failed: %a" Slirp_stack.Client.Icmpv41.pp_error e
          | Ok () ->
            Host.Time.sleep_ns (Duration.of_sec 1)
            >>= fun () ->
            loop (seq + 1)
        end in
      loop 0
    )
  end

let test_two_pings () =
  Queue.clear Slirp_stack.Client.Icmpv41.packets;
  Host.Main.run begin
    Slirp_stack.with_stack ~pcap:"test_two_pings.pcap" (fun _ stack ->
      let rec loop seq =
        let id_1 = 0x1234 in
        let id_2 = 0x4321 in
        let ping_1 = Packets.icmp_echo_request ~id:id_1 ~seq ~len:0 in
        let ping_2 = Packets.icmp_echo_request ~id:id_2 ~seq ~len:128 in

        Printf.printf "sending ping\n%!";
        Slirp_stack.Client.Icmpv41.write stack.Slirp_stack.Client.icmpv4 ~dst:google_1 ping_1
        >>= function
        | Error e -> failf "Icmpv41.write failed: %a" Slirp_stack.Client.Icmpv41.pp_error e
        | Ok () ->
          Slirp_stack.Client.Icmpv41.write stack.Slirp_stack.Client.icmpv4 ~dst:google_2 ping_2
          >>= function
          | Error e -> failf "Icmpv41.write failed: %a" Slirp_stack.Client.Icmpv41.pp_error e
          | Ok () ->
            Host.Time.sleep_ns (Duration.of_sec 1)
            >>= fun () ->
            if Queue.length Slirp_stack.Client.Icmpv41.packets > 0 then begin
              let all = Queue.fold (fun xs x -> x :: xs) [] Slirp_stack.Client.Icmpv41.packets in
              let one, two = List.partition (fun (_, _, id) -> id = id_1) all in
              let src_one = List.map (fun (src, _, _) -> src) one in
              let src_two = List.map (fun (src, _, _) -> src) two in
              let one_from_1, one_from_2 = List.partition (fun src -> Ipaddr.V4.compare google_1 src = 0) src_one in
              let two_from_1, two_from_2 = List.partition (fun src -> Ipaddr.V4.compare google_1 src = 0) src_two in
              (* all id_2 (two) should have come from google_2 *)
              (* all id_1 (one) should have come from google_1 *)
              if two_from_1 <> [] || one_from_2 <> []
              then failf "Received pings from the wrong IP addresses"
              else
                if one_from_1 <> [] && two_from_2 <> [] then begin
                  Printf.printf "Received %d pings from google_1 and %d from google_2\n%!"
                    (List.length one_from_1) (List.length two_from_2);
                  Lwt.return_unit
                end else loop (seq + 1)
            end else loop (seq + 1) in
      loop 0
    )
  end

let tests = [
  "ICMP: ping 8.8.8.8", [
    "check that we can ping google's DNS", `Quick,
    test_ping
  ] ;

  "ICMP: two pings", [
    "check that two processes can send pings without the responses getting confused", `Quick,
    test_two_pings
  ];
]

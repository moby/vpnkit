open OUnit2
open Test_mdns_resolver_mirage
open Lwt
open Dns.Packet
open Result

let assert_packet = Test_mdns_responder.assert_packet

let run_timeout thread =
  Lwt_main.run (
    Lwt.pick [
      (Lwt_unix.sleep 1.0 >>= fun () -> return_unit);
      thread
    ])

let client_ip = Ipaddr.V4.of_string_exn "10.0.0.3"
let server_ip = Ipaddr.V4.of_string_exn "10.0.0.2"

let simulate_query
    ?(from_ip=client_ip) ?(from_port=12345) ?(to_ip=server_ip)
    ?(id=999) ?(detail=good_detail)
    ?(answers=[bad_answer])
    stack question
  =
  let request = {
    id;
    detail= {qr=Query; opcode=Standard; aa=false; tc=false; rd=true; ra=false; rcode=NoError};
    questions=[question]; answers=[]; authorities=[]; additionals=[];
  } in
  let buf = marshal request in
  let listener_thread = match MockStack.udpv4_listeners stack ~dst_port:53 with
    | None -> assert_failure "missing listener"
    | Some listener -> listener ~src:from_ip ~dst:to_ip ~src_port:from_port buf
  in
  Lwt_main.run (
    Lwt.pick [
      Lwt_unix.sleep 1.0;
      listener_thread
    ])

let filename1 = "file1.zone"
let filename2 = "file2.zone"

let zone1 = "
; $TTL used for all RRs without explicit TTL value


$ORIGIN example1.com.
$TTL    3600 ; 24 hours could have been written as 24h or 1d
example1.com. 3600 IN  SOA (
    ns1.example1.com. username.example1.com. 1136975101 ; hello!
    3600 1800 3024000 1800
                 )
example1.com.       3600 IN  NS     ns1
example1.com.       3600 IN  NS     ns2
;; example1.com.       3600 IN  MX  1   mail
ns1  3600  IN A      192.168.1.11
ns2  3600  IN A      192.168.1.11
www  3600  IN  A      192.168.1.11
"

let zone2 = "
; $TTL used for all RRs without explicit TTL value


$ORIGIN example2.net.
$TTL    3600 ; 24 hours could have been written as 24h or 1d
example2.net. 3600 IN  SOA (
    ns1.example2.net. username.example2.net. 1136975101 ; hello!
    3600 1800 3024000 1800
                 )
example2.net.       3600 IN  NS     ns1
example2.net.       3600 IN  NS     ns2
;; example2.net.       3600 IN  MX  1   mail
ns1  3600  IN A      192.168.1.11
ns2  3600  IN A      192.168.1.11
www  3600  IN  A      192.168.1.11
"

let zones = [(filename1, Cstruct.of_string zone1); (filename2, Cstruct.of_string zone2)]

module MockKV = struct
  type +'a io = 'a Lwt.t
  type error = Mirage_kv.error
  let pp_error = Mirage_kv.pp_error
  type page_aligned_buffer = Cstruct.t
  type t = unit

  let instance = ()
  let disconnect t = Lwt.return_unit

  let read t name off len =
    return (
      try
        let buf = List.assoc name zones in
        Ok Int64.([Cstruct.sub buf (to_int off) (to_int len)])
      with exn ->
        Error (`Unknown_key name)
    )

  let size t name =
    return (
      try
        Ok (List.assoc name zones |> Cstruct.len |> Int64.of_int)
      with exn ->
        Error (`Unknown_key name)
    )

  let mem t name =
    return
      (try let _ = List.assoc name zones in Ok true
       with exn -> Ok false)
end

let assert_rrlist msg expected_strs actual_rrlist =
  let expected_sorted = List.sort String.compare expected_strs in
  let actual_sorted = actual_rrlist |> List.map rr_to_string |> List.sort String.compare in
  List.iter2 (fun expected actual ->
      assert_equal ~msg ~printer:(fun s -> s) expected actual
    ) expected_sorted actual_sorted

let tests =
  "Dns_server_mirage" >:::
  [
    "serve_with_zonefiles" >:: (fun test_ctxt ->
        let stack = create_stack () in
        let u = MockStack.udpv4 stack in
        let module S = Dns_server_mirage.Make(MockKV)(MockStack) in
        let server = S.create stack (MockKV.instance) in
        let thread = S.serve_with_zonefiles server ~port:53 ~zonefiles:[filename1; filename2] in

        begin
          (* Simulate a simple query *)
          let name1 = Dns.Name.of_string "www.example1.com" in
          let question1 = { q_name=name1; q_type=Q_A; q_unicast=Q_Normal; q_class=Q_IN; } in
          simulate_query ~id:3848 stack question1;

          (* Verify that the response is correct *)
          let w = MockUdpv4.pop_write u in
          assert_equal ~printer:string_of_int 53 w.src_port;
          assert_ip client_ip w.dst;
          assert_equal ~printer:string_of_int 12345 w.dst_port;
          let packet = parse w.buf in
          assert_packet ~prefix:"1" ~id:3848 packet
            {qr=Response; opcode=Standard; aa=true; tc=false; rd=true; ra=false; rcode=NoError}
            1 1 2 3;
          assert_equal ~msg:"q1" ~printer:(fun s -> s) "www.example1.com. <A|IN>" (packet.questions |> List.hd |> question_to_string);
          assert_rrlist "an1" [
            "www.example1.com <IN|3600> [A (192.168.1.11)]";
          ] packet.answers;
          assert_rrlist "au1" [
            "example1.com <IN|3600> [NS (ns1.example1.com)]";
            "example1.com <IN|3600> [NS (ns2.example1.com)]";
          ] packet.authorities;
          assert_rrlist "ad1" [
            " <IN|32768> [EDNS0 (version:0, UDP: 1500, flags: do)]";
            "ns1.example1.com <IN|3600> [A (192.168.1.11)]";
            "ns2.example1.com <IN|3600> [A (192.168.1.11)]";
          ] packet.additionals;
        end;

        begin
          (* Simulate a simple query *)
          let name2 = Dns.Name.of_string "www.example2.net" in
          let question2 = { q_name=name2; q_type=Q_A; q_unicast=Q_Normal; q_class=Q_IN; } in
          simulate_query ~id:19560 stack question2;

          (* Verify that the response is correct *)
          let w = MockUdpv4.pop_write u in
          assert_equal ~printer:string_of_int 53 w.src_port;
          assert_ip client_ip w.dst;
          assert_equal ~printer:string_of_int 12345 w.dst_port;
          let packet = parse w.buf in
          assert_packet ~prefix:"2" ~id:19560 packet
            {qr=Response; opcode=Standard; aa=true; tc=false; rd=true; ra=false; rcode=NoError}
            1 1 2 3;
          assert_equal ~msg:"q2" ~printer:(fun s -> s) "www.example2.net. <A|IN>" (packet.questions |> List.hd |> question_to_string);
          assert_rrlist "an2" [
            "www.example2.net <IN|3600> [A (192.168.1.11)]";
          ] packet.answers;
          assert_rrlist "au2" [
            "example2.net <IN|3600> [NS (ns1.example2.net)]";
            "example2.net <IN|3600> [NS (ns2.example2.net)]";
          ] packet.authorities;
          assert_rrlist "ad2" [
            " <IN|32768> [EDNS0 (version:0, UDP: 1500, flags: do)]";
            "ns1.example2.net <IN|3600> [A (192.168.1.11)]";
            "ns2.example2.net <IN|3600> [A (192.168.1.11)]";
          ] packet.additionals;
        end;

        run_timeout thread
      );
  ]

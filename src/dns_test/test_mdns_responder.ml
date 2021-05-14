
open OUnit2
open Printf
open Test_packet

let load_file path =
  let ch = open_in path in
  let n = in_channel_length ch in
  let data = Bytes.create n in
  really_input ch data 0 n;
  close_in ch;
  data

let assert_range low high actual =
  assert_bool (sprintf "%f not in range %f <= x < %f" actual low high) (low <= actual && actual < high)

open Dns
open Packet

let assert_packet ?(prefix="") ?(id=0) packet expected_detail nq nan nau nad =
  assert_equal ~msg:(prefix ^ "id") ~printer:string_of_int id packet.id;
  assert_equal ~msg:(prefix ^ "qr") expected_detail.qr packet.detail.qr;
  assert_equal ~msg:(prefix ^ "opcode") ~printer:opcode_to_string expected_detail.opcode packet.detail.opcode;
  assert_equal ~msg:(prefix ^ "aa") ~printer:string_of_bool expected_detail.aa packet.detail.aa;
  assert_equal ~msg:(prefix ^ "tc") ~printer:string_of_bool expected_detail.tc packet.detail.tc;
  assert_equal ~msg:(prefix ^ "rd") ~printer:string_of_bool expected_detail.rd packet.detail.rd;
  assert_equal ~msg:(prefix ^ "ra") ~printer:string_of_bool expected_detail.ra packet.detail.ra;
  assert_equal ~msg:(prefix ^ "rcode") ~printer:rcode_to_string expected_detail.rcode packet.detail.rcode;
  assert_equal ~msg:(prefix ^ "#qu") nq (List.length packet.questions);
  assert_equal ~msg:(prefix ^ "#an") nan (List.length packet.answers);
  assert_equal ~msg:(prefix ^ "#au") nau (List.length packet.authorities);
  assert_equal ~msg:(prefix ^ "#ad") nad (List.length packet.additionals)

let run_timeout thread =
  Lwt_main.run (
    Lwt.pick [
      Lwt_unix.sleep 1.0;
      thread
    ])

let verify_probe1 ~prefix sleepl txlist cond =
  (* Wait for the first probe to be sent and the second sleep *)
  Lwt_condition.signal cond ();  (* Unblock sleep *)
  assert_equal ~msg:(prefix ^ "#sleepl second") ~printer:string_of_int 2 (List.length !sleepl);
  assert_equal ~msg:(prefix ^ "#txlist second") ~printer:string_of_int 1 (List.length !txlist);
  (* Verify the first transmitted probe *)
  let (txaddr, txbuf) = List.hd !txlist in
  let (txip, txport) = txaddr in
  assert_equal ~msg:(prefix ^ "txip") ~printer:(fun s -> s) "224.0.0.251" (Ipaddr.V4.to_string txip);
  assert_equal ~msg:(prefix ^ "txport") ~printer:string_of_int 5353 txport;
  let packet = parse txbuf in
  let expected = "0000 Query:0 na:c:nr:rn 0 <qs:unique.local. <ANY_TYP|IN|QU>> <an:> <au:unique.local <IN,flush|120> [A (1.2.3.4)]> <ad:>" in
  assert_equal ~msg:(prefix ^ "rr") ~printer:(fun s -> s) expected (to_string packet);
  (* Verify the sleep duration *)
  assert_equal ~msg:(prefix ^ "second sleep should be 250 ms") ~printer:string_of_float 0.25 (List.hd !sleepl);
  txaddr, txbuf

let verify_probe2 ~prefix sleepl txlist cond txaddr txbuf =
  (* Wait for the second probe to be sent and the third sleep *)
  Lwt_condition.signal cond ();  (* Unblock sleep *)
  assert_equal ~msg:(prefix ^ "#sleepl third") ~printer:string_of_int 3 (List.length !sleepl);
  assert_equal ~msg:(prefix ^ "#txlist third") ~printer:string_of_int 2 (List.length !txlist);
  (* The second packet should be exactly the same *)
  let (txaddr2, txbuf2) = List.hd !txlist in
  assert_equal ~msg:(prefix ^ "txaddr2") txaddr txaddr2;
  assert_equal ~msg:(prefix ^ "txbuf2") txbuf txbuf2;
  (* Verify the sleep duration *)
  assert_equal ~msg:(prefix ^ "third sleep should be 250 ms") ~printer:string_of_float 0.25 (List.hd !sleepl)

let verify_probe3 ~prefix sleepl txlist cond txaddr txbuf =
  (* Wait for the third probe to be sent and the fourth sleep *)
  Lwt_condition.signal cond ();  (* Unblock sleep *)
  assert_equal ~msg:(prefix ^ "#sleepl fourth") ~printer:string_of_int 4 (List.length !sleepl);
  assert_equal ~msg:(prefix ^ "#txlist fourth") ~printer:string_of_int 3 (List.length !txlist);
  (* The third packet should be exactly the same *)
  let (txaddr3, txbuf3) = List.hd !txlist in
  assert_equal ~msg:(prefix ^ "txaddr3") txaddr txaddr3;
  assert_equal ~msg:(prefix ^ "txbuf3") txbuf txbuf3;
  (* Verify the sleep duration *)
  assert_equal ~msg:(prefix ^ "fourth sleep should be 250 ms") ~printer:string_of_float 0.25 (List.hd !sleepl)


let tests =
  "Mdns_responder" >:::
  [
    "q-A-AAAA" >:: (fun test_ctxt ->
        let txlist = ref [] in
        let module MockTransport = struct
          let alloc () = Cstruct.create 4096
          let write addr buf =
            txlist := (addr, buf) :: !txlist;
            Lwt.return ()
          let sleep t =
            assert_range 0.02 0.12 t;
            Lwt.return ()
        end in
        let module Responder = Mdns_responder.Make(MockTransport) in
        let zonebuf = load_file "test_mdns.zone" in
        let responder = Responder.of_zonebufs [zonebuf] in
        let raw = load_packet "mdns-q-A-AAAA.pcap" in
        let src = (Ipaddr.V4.of_string_exn "10.0.0.1", 5353) in
        let dst = (Ipaddr.V4.of_string_exn "224.0.0.251", 5353) in
        let thread = Responder.process responder ~src ~dst raw in
        run_timeout thread;

        (* Verify the transmitted packet *)
        assert_equal 1 (List.length !txlist);
        let (txaddr, txbuf) = List.hd !txlist in
        let (txip, txport) = txaddr in
        assert_equal ~printer:(fun s -> s) "224.0.0.251" (Ipaddr.V4.to_string txip);
        assert_equal ~printer:string_of_int 5353 txport;
        let packet = parse txbuf in
        assert_packet packet {qr=Response; opcode=Standard; aa=true; tc=false; rd=false; ra=false; rcode=NoError} 0 1 0 0;

        let a = List.hd packet.answers in
        assert_equal ~msg:"name" "mirage1.local" (Name.to_string a.name);
        assert_equal ~msg:"cls" RR_IN a.cls;
        assert_equal ~msg:"flush" false a.flush;
        assert_equal ~msg:"ttl" (Int32.of_int 120) a.ttl;
        match a.rdata with
        | A addr -> assert_equal ~msg:"A" "10.0.0.2" (Ipaddr.V4.to_string addr)
        | _ -> assert_failure "RR type";
      );

    "q-legacy" >:: (fun test_ctxt ->
        let txlist = ref [] in
        let module MockTransport = struct
          let alloc () = Cstruct.create 4096
          let write addr buf =
            txlist := (addr, buf) :: !txlist;
            Lwt.return ()
          let sleep t =
            assert_equal ~msg:"delay" 0.0 t;
            Lwt.return ()
        end in
        let module Responder = Mdns_responder.Make(MockTransport) in
        let zonebuf = load_file "test_mdns.zone" in
        let responder = Responder.of_zonebufs [zonebuf] in
        let raw = load_packet "mdns-q-A-legacy.pcap" in
        (* Source port != 5353 indicates a legacy request *)
        let src = (Ipaddr.V4.of_string_exn "10.0.0.1", 12345) in
        let dst = (Ipaddr.V4.of_string_exn "224.0.0.251", 5353) in
        let thread = Responder.process responder ~src ~dst raw in
        run_timeout thread;

        (* Verify the transmitted packet *)
        assert_equal 1 (List.length !txlist);
        let (txaddr, txbuf) = List.hd !txlist in
        let (txip, txport) = txaddr in
        assert_equal ~printer:(fun s -> s) "10.0.0.1" (Ipaddr.V4.to_string txip);
        assert_equal ~printer:string_of_int 12345 txport;
        let packet = parse txbuf in
        assert_packet ~id:0x1df9 packet {qr=Response; opcode=Standard; aa=true; tc=false; rd=true; ra=false; rcode=NoError} 1 1 0 0;

        let q = List.hd packet.questions in
        assert_equal ~msg:"q_name" "mirage1.local" (Name.to_string q.q_name);
        assert_equal ~msg:"q_type" Q_A q.q_type;
        assert_equal ~msg:"q_class" Q_IN q.q_class;
        assert_equal ~msg:"q_unicast" Q_Normal q.q_unicast;

        let a = List.hd packet.answers in
        assert_equal ~msg:"name" "mirage1.local" (Name.to_string a.name);
        assert_equal ~msg:"cls" RR_IN a.cls;
        assert_equal ~msg:"flush" false a.flush;
        assert_equal ~msg:"ttl" (Int32.of_int 10) a.ttl;  (* rfc6762 s6.7_p2_c1 *)
        match a.rdata with
        | A addr -> assert_equal ~msg:"A" "10.0.0.2" (Ipaddr.V4.to_string addr)
        | _ -> assert_failure "RR type";
      );

    "q-PTR-first" >:: (fun test_ctxt ->
        let txlist = ref [] in
        let module MockTransport = struct
          let alloc () = Cstruct.create 4096
          let write addr buf =
            txlist := (addr, buf) :: !txlist;
            Lwt.return ()
          let sleep t =
            assert_range 0.02 0.12 t;
            Lwt.return ()
        end in
        let module Responder = Mdns_responder.Make(MockTransport) in
        let zonebuf = load_file "test_mdns.zone" in
        let responder = Responder.of_zonebufs [zonebuf] in
        let raw = load_packet "mdns-q-PTR-first.pcap" in
        let src = (Ipaddr.V4.of_string_exn "10.0.0.1", 5353) in
        let dst = (Ipaddr.V4.of_string_exn "224.0.0.251", 5353) in
        let thread = Responder.process responder ~src ~dst raw in
        run_timeout thread;

        (* Verify the transmitted packet *)
        assert_equal 1 (List.length !txlist);
        let (txaddr, txbuf) = List.hd !txlist in
        let (txip, txport) = txaddr in
        assert_equal ~printer:(fun s -> s) "224.0.0.251" (Ipaddr.V4.to_string txip);
        assert_equal ~printer:string_of_int 5353 txport;
        let packet = parse txbuf in
        assert_packet packet {qr=Response; opcode=Standard; aa=true; tc=false; rd=false; ra=false; rcode=NoError} 0 3 0 6;

        (* Verify the PTR records *)
        (* Unfortunately the order of records is non-deterministic so we build a sorted list first *)
        let ptrl = ["dugite._snake._tcp.local"; "king brown._snake._tcp.local"; "tiger._snake._tcp.local"] in
        let rec get_ptr_list rrs rest =
          begin
            match rrs with
            | [] -> rest;
            | rr::tl ->
              begin
                assert_equal ~msg:"name" ~printer:(fun s -> s) "_snake._tcp.local" (Name.to_string rr.name);
                assert_equal ~msg:"cls" RR_IN rr.cls;
                assert_equal ~msg:"flush" false rr.flush;
                assert_equal ~msg:"ttl" ~printer:Int32.to_string (Int32.of_int 120) rr.ttl;
                match rr.rdata with
                | PTR name ->
                  get_ptr_list tl ((Name.to_string name) :: rest)
                | _ -> assert_failure "Not PTR";
              end
          end
        in
        let ptr_list = get_ptr_list packet.answers [] in
        let ptr_sorted = List.sort String.compare ptr_list in
        let rec dump_str_l l =
          match l with
          | [] -> ""
          | hd::tl -> hd ^ "; " ^ (dump_str_l tl) in
        assert_equal ~printer:dump_str_l ptrl ptr_sorted;

        (* Verify the additional SRV, TXT and A records *)
        (* First create association lists for the expected results *)
        let srvl = ["fake2.local"; "fake3.local"; "fake1.local"] in
        let srv_assoc = List.combine ptrl srvl in
        let txt_assoc = List.combine ptrl ["species=Pseudonaja affinis"; "species=Pseudechis australis"; "species=Notechis scutatus"] in
        let a_assoc = List.combine srvl ["127.0.0.95"; "127.0.0.96"; "127.0.0.94"] in
        List.iter (fun rr ->
            let key = String.lowercase_ascii (Name.to_string rr.name) in
            match rr.rdata with
            | SRV (priority, weight, port, srv) ->
              assert_equal 0 priority;
              assert_equal 0 weight;
              assert_equal 33333 port;
              assert_equal ~printer:(fun s -> s) (List.assoc key srv_assoc) (Name.to_string srv)
            | TXT txtl ->
              assert_equal 2 (List.length txtl);
              assert_equal "txtvers=1" (List.hd txtl);
              assert_equal ~printer:(fun s -> s) (List.assoc key txt_assoc) (List.nth txtl 1)
            | A ip ->
              assert_equal ~printer:(fun s -> s) (List.assoc key a_assoc) (Ipaddr.V4.to_string ip)
            | _ -> assert_failure "Not SRV, TXT or A"
          ) packet.additionals;
      );

    "q-PTR-known" >:: (fun test_ctxt ->
        let module MockTransport = struct
          let alloc () = Cstruct.create 4096
          let write addr buf =
            assert_failure "write shouldn't be called"
          let sleep t =
            assert_failure "sleepfn shouldn't be called"
        end in
        let module Responder = Mdns_responder.Make(MockTransport) in
        let zonebuf = load_file "test_mdns.zone" in
        let responder = Responder.of_zonebufs [zonebuf] in
        let raw = load_packet "mdns-q-PTR-known.pcap" in
        let src = (Ipaddr.V4.of_string_exn "10.0.0.1", 5353) in
        let dst = (Ipaddr.V4.of_string_exn "224.0.0.251", 5353) in
        (* Given that the query already contains known answers for
           all relevant records, there should be no reply at all. *)
        let thread = Responder.process responder ~src ~dst raw in
        run_timeout thread;
      );

    "unique" >:: (fun test_ctxt ->
        let txlist = ref [] in
        let sleepl = ref [] in
        let module MockTransport = struct
          let alloc () = Cstruct.create 4096
          let write addr buf =
            txlist := (addr, buf) :: !txlist;
            Lwt.return ()
          let sleep t =
            sleepl := t :: !sleepl;
            Lwt.return ()
        end in
        let module Responder = Mdns_responder.Make(MockTransport) in
        let zonebuf = load_file "test_mdns.zone" in
        let responder = Responder.of_zonebufs [zonebuf] in

        let module DR = Dns.RR in
        let module H = Hashcons in
        let name = Name.of_string "mirage1.local" in
        begin
          let key = Name.to_key name in
          match Dns.Trie.simple_lookup key (Responder.trie responder) with
          | None -> assert_failure "mirage1.local not found";
          | Some node ->
            assert_equal ~msg:"owner" ~printer:(fun s -> s) "mirage1.local" (Name.to_string node.DR.owner.H.node);
        end;

        (* Add a unique hostname *)
        let unique_ip = Ipaddr.V4.of_string_exn "1.2.3.4" in
        let unique_name_str = "unique.local" in
        let name = Name.of_string unique_name_str in
        Responder.add_unique_hostname responder name unique_ip;
        begin
          let key = Name.to_key name in
          match Dns.Trie.simple_lookup key (Responder.trie responder) with
          | None -> assert_failure "unique.local not found";
          | Some node ->
            assert_equal ~msg:"owner" ~printer:(fun s -> s) unique_name_str (Name.to_string node.DR.owner.H.node);
        end
      );

    "probe-normal" >:: (fun test_ctxt ->
        let txlist = ref [] in
        let cond = Lwt_condition.create () in
        let sleepl = ref [] in
        let module MockTransport = struct
          let alloc () = Cstruct.create 4096
          let write addr buf =
            txlist := (addr, buf) :: !txlist;
            Lwt.return ()
          let sleep t =
            sleepl := t :: !sleepl;
            Lwt_condition.wait cond
        end in
        let module Responder = Mdns_responder.Make(MockTransport) in
        let zonebuf = load_file "test_mdns.zone" in
        let responder = Responder.of_zonebufs [zonebuf] in

        (* Add a unique hostname *)
        let unique_ip = Ipaddr.V4.of_string_exn "1.2.3.4" in
        let unique_str = "unique.local" in
        let name = Name.of_string unique_str in
        Responder.add_unique_hostname responder name unique_ip;

        (* Create the probe thread *)
        let probe_thread = Responder.first_probe responder in
        (* Wait for the first sleep *)
        assert_equal ~msg:"#sleepl first" ~printer:string_of_int 1 (List.length !sleepl);
        assert_equal ~msg:"#txlist first" ~printer:string_of_int 0 (List.length !txlist);
        (* Verify the sleep duration *)
        assert_range 0.0 0.25 (List.hd !sleepl);

        (* Verify the first probe *)
        let prefix = "probe-normal:" in
        let txaddr, txbuf = verify_probe1 ~prefix sleepl txlist cond in
        (* Verify the second probe *)
        verify_probe2 ~prefix sleepl txlist cond txaddr txbuf;
        (* Verify the third probe *)
        verify_probe3 ~prefix sleepl txlist cond txaddr txbuf;

        (* Make sure the probe thread has finished *)
        Lwt_condition.signal cond ();  (* Unblock sleep *)
        while Lwt.is_sleeping probe_thread do
          Lwt_condition.signal cond ();
          Lwt_engine.iter false
        done;

        (* Announcement stage *)
        run_timeout (Responder.announce responder ~repeat:1);
        assert_equal ~msg:"#sleepl announce" ~printer:string_of_int 4 (List.length !sleepl);
        assert_equal ~msg:"#txlist announce" ~printer:string_of_int 4 (List.length !txlist);
        let (txaddr4, txbuf) = List.hd !txlist in
        assert_equal ~msg:"txaddr4" txaddr txaddr4;
        let packet = parse txbuf in
        assert_packet packet {qr=Response; opcode=Standard; aa=true; tc=false; rd=false; ra=false; rcode=NoError} 0 18 0 0;

        (* Verify that the cache flush bit is set on the announced unique record *)
        let rr = List.find (fun rr -> (Name.to_string rr.name) = "unique.local") packet.answers in
        assert_equal ~msg:"unique name" ~printer:(fun s -> s) "unique.local" (Name.to_string rr.name);
        assert_equal ~msg:"unique cls" RR_IN rr.cls;
        assert_equal ~msg:"unique flush" true rr.flush;
        assert_equal ~msg:"unique ttl" (Int32.of_int 120) rr.ttl;
        begin
          match rr.rdata with
          | A addr -> assert_equal ~msg:"unique A" "1.2.3.4" (Ipaddr.V4.to_string addr)
          | _ -> assert_failure "unique RR type";
        end;

        run_timeout (Responder.stop_probe responder)
      );

    "probe-conflict" >:: (fun test_ctxt ->
        let txlist = ref [] in
        let cond = Lwt_condition.create () in
        let sleepl = ref [] in
        let module MockTransport = struct
          let alloc () = Cstruct.create 4096
          open Lwt
          let write addr buf =
            txlist := (addr, buf) :: !txlist;
            return_unit
          let sleep t =
            sleepl := t :: !sleepl;
            (* printf "sleep %f; #sleepl %d\n" t (List.length !sleepl); *)
            Lwt_condition.wait cond >>= fun () ->
            (* printf "sleep done\n"; *)
            return_unit
        end in
        let module Responder = Mdns_responder.Make(MockTransport) in
        let zonebuf = load_file "test_mdns.zone" in
        let responder = Responder.of_zonebufs [zonebuf] in

        (* Add a unique hostname *)
        let unique_ip = Ipaddr.V4.of_string_exn "1.2.3.4" in
        let unique_str = "unique.local" in
        let name = Name.of_string unique_str in
        Responder.add_unique_hostname responder name unique_ip;

        (* Create the probe thread *)
        let _ = Responder.first_probe responder in
        (* Wait for the first sleep *)
        assert_equal ~msg:"#sleepl first" ~printer:string_of_int 1 (List.length !sleepl);
        assert_equal ~msg:"#txlist first" ~printer:string_of_int 0 (List.length !txlist);
        (* Verify the sleep duration *)
        assert_range 0.0 0.25 (List.hd !sleepl);

        (* Verify the first probe *)
        let txaddr, txbuf = verify_probe1 ~prefix:"probe-conflict:" sleepl txlist cond in

        (* Simulate a conflicting response *)
        let response_src_ip = Ipaddr.V4.of_string_exn "10.0.0.3" in
        let unique_name = Name.of_string unique_str in
        let answer = { name=unique_name; cls=RR_IN; flush=true; ttl=120_l; rdata=A response_src_ip } in
        let response = {
          id=0;
          detail= {qr=Response; opcode=Standard; aa=true; tc=false; rd=false; ra=false; rcode=NoError};
          questions=[]; answers=[answer]; authorities=[]; additionals=[];
        } in
        let response_buf = marshal response in
        let _ = Responder.process responder ~src:(response_src_ip, 5353) ~dst:txaddr response_buf in

        (* A new probe cycle begins *)
        assert_equal ~msg:"#sleepl second2" ~printer:string_of_int 3 (List.length !sleepl);
        assert_equal ~msg:"#txlist second2" ~printer:string_of_int 2 (List.length !txlist);
        (* Verify the probe *)
        let (txaddr, txbuf) = List.hd !txlist in
        let (txip, txport) = txaddr in
        assert_equal ~printer:(fun s -> s) "224.0.0.251" (Ipaddr.V4.to_string txip);
        assert_equal ~printer:string_of_int 5353 txport;
        let packet = parse txbuf in
        let expected = "0000 Query:0 na:c:nr:rn 0 <qs:unique2.local. <ANY_TYP|IN|QU>> <an:> <au:unique2.local <IN,flush|120> [A (1.2.3.4)]> <ad:>" in
        assert_equal ~msg:"rr" ~printer:(fun s -> s) expected (to_string packet);
        (* Verify the sleep duration *)
        assert_equal ~msg:"second sleep should be 250 ms" ~printer:string_of_float 0.25 (List.hd !sleepl);
        (* Ignore the rest of the cycle *)
      );

    "probe-identical" >:: (fun test_ctxt ->
        let txlist = ref [] in
        let cond = Lwt_condition.create () in
        let sleepl = ref [] in
        let module MockTransport = struct
          let alloc () = Cstruct.create 4096
          open Lwt
          let write addr buf =
            txlist := (addr, buf) :: !txlist;
            return_unit
          let sleep t =
            sleepl := t :: !sleepl;
            Lwt_condition.wait cond >>= fun () ->
            return_unit
        end in
        let module Responder = Mdns_responder.Make(MockTransport) in
        let zonebuf = load_file "test_mdns.zone" in
        let responder = Responder.of_zonebufs [zonebuf] in

        (* Add a unique hostname *)
        let unique_ip = Ipaddr.V4.of_string_exn "1.2.3.4" in
        let unique_str = "unique.local" in
        let name = Name.of_string unique_str in
        Responder.add_unique_hostname responder name unique_ip;

        (* Create the probe thread *)
        let probe_thread = Responder.first_probe responder in
        assert_equal ~msg:"#sleepl first" ~printer:string_of_int 1 (List.length !sleepl);

        (* Verify the first probe *)
        let prefix = "probe-identical:" in
        let txaddr, txbuf = verify_probe1 ~prefix sleepl txlist cond in

        (* Simulate a response that matches the unique record, and is therefore not a conflict *)
        let response_src_ip = Ipaddr.V4.of_string_exn "10.0.0.3" in
        let unique_name = Name.of_string unique_str in
        let answer = { name=unique_name; cls=RR_IN; flush=true; ttl=120_l; rdata=A unique_ip } in
        let response = {
          id=0;
          detail= {qr=Response; opcode=Standard; aa=true; tc=false; rd=false; ra=false; rcode=NoError};
          questions=[]; answers=[answer]; authorities=[]; additionals=[];
        } in
        let response_buf = marshal response in
        let _ = Responder.process responder ~src:(response_src_ip, 5353) ~dst:txaddr response_buf in

        (* Verify the second probe *)
        verify_probe2 ~prefix sleepl txlist cond txaddr txbuf;
        (* Simulate the same response again *)
        let _ = Responder.process responder ~src:(response_src_ip, 5353) ~dst:txaddr response_buf in

        (* Verify the third probe *)
        verify_probe3 ~prefix sleepl txlist cond txaddr txbuf;
        (* Simulate the same response again *)
        let _ = Responder.process responder ~src:(response_src_ip, 5353) ~dst:txaddr response_buf in

        (* Make sure the probe thread has finished *)
        Lwt_condition.signal cond ();  (* Unblock sleep *)
        while Lwt.is_sleeping probe_thread do
          Lwt_condition.signal cond ();
          Lwt_engine.iter false
        done;

        (* Announcement stage *)
        run_timeout (Responder.announce responder ~repeat:1);
        assert_equal ~msg:"#sleepl announce" ~printer:string_of_int 4 (List.length !sleepl);
        assert_equal ~msg:"#txlist announce" ~printer:string_of_int 4 (List.length !txlist);
        let (txaddr4, txbuf) = List.hd !txlist in
        assert_equal ~msg:"txaddr4" txaddr txaddr4;
        let packet = parse txbuf in
        assert_packet packet {qr=Response; opcode=Standard; aa=true; tc=false; rd=false; ra=false; rcode=NoError} 0 18 0 0;

        (* Verify that the cache flush bit is set on the announced unique record *)
        let rr = List.find (fun rr -> (Name.to_string rr.name) = "unique.local") packet.answers in
        assert_equal ~msg:"unique name" ~printer:(fun s -> s) "unique.local" (Name.to_string rr.name);
        assert_equal ~msg:"unique cls" RR_IN rr.cls;
        assert_equal ~msg:"unique flush" true rr.flush;
        assert_equal ~msg:"unique ttl" (Int32.of_int 120) rr.ttl;
        begin
          match rr.rdata with
          | A addr -> assert_equal ~msg:"unique A" "1.2.3.4" (Ipaddr.V4.to_string addr)
          | _ -> assert_failure "unique RR type";
        end;

        run_timeout (Responder.stop_probe responder)
      );

    "probe-simultaneous" >:: (fun test_ctxt ->
        let txlist = ref [] in
        let cond = Lwt_condition.create () in
        let sleepl = ref [] in
        let module MockTransport = struct
          let alloc () = Cstruct.create 4096
          open Lwt
          let write addr buf =
            txlist := (addr, buf) :: !txlist;
            return_unit
          let sleep t =
            sleepl := t :: !sleepl;
(*             printf "sleep %f; #sleepl %d\n" t (List.length !sleepl); *)
            Lwt_condition.wait cond >>= fun () ->
(*             printf "sleep done\n"; *)
            return_unit
        end in
        let module Responder = Mdns_responder.Make(MockTransport) in
        let zonebuf = load_file "test_mdns.zone" in
        let responder = Responder.of_zonebufs [zonebuf] in

        (* Add a unique hostname *)
        let unique_ip = Ipaddr.V4.of_string_exn "1.2.3.4" in
        let unique_str = "unique.local" in
        let name = Name.of_string unique_str in
        Responder.add_unique_hostname responder name unique_ip;

        (* Create the probe thread *)
        let _ = Responder.first_probe responder in
        (* Wait for the first sleep *)
        assert_equal ~msg:"#sleepl first" ~printer:string_of_int 1 (List.length !sleepl);
        assert_equal ~msg:"#txlist first" ~printer:string_of_int 0 (List.length !txlist);
        (* Verify the sleep duration *)
        assert_range 0.0 0.25 (List.hd !sleepl);

        (* Verify the first probe *)
        let prefix = "probe-simultaneous:" in
        let txaddr, txbuf = verify_probe1 ~prefix sleepl txlist cond in

        (* Simulate a conflicting simultaneous probe *)
        (* The received data is lexicographically greater and therefore we lose *)
        let conflict_src_ip = Ipaddr.V4.of_string_exn "10.0.0.3" in
        let unique_name = Name.of_string unique_str in
        let question = { q_name=unique_name; q_type=Q_ANY_TYP; q_class=Q_IN; q_unicast=Q_mDNS_Unicast } in
        let auth = { name=unique_name; cls=RR_IN; flush=true; ttl=120_l; rdata=A conflict_src_ip } in
        let query = {
          id=0;
          detail= {qr=Query; opcode=Standard; aa=false; tc=false; rd=false; ra=false; rcode=NoError};
          questions=[question]; answers=[]; authorities=[auth]; additionals=[];
        } in
        let query_buf = marshal query in
        let _ = Responder.process responder ~src:(conflict_src_ip, 5353) ~dst:txaddr query_buf in

        (* One-second delay before restarting the probe cycle *)
        (* NOTE: the previous 250 ms was cancelled *)
        assert_equal ~msg:"#sleepl backoff" ~printer:string_of_int 3 (List.length !sleepl);
        assert_equal ~msg:"#txlist backoff" ~printer:string_of_int 1 (List.length !txlist);
        assert_equal ~msg:"expected one-second delay" ~printer:string_of_float 1.0 (List.hd !sleepl);

        (* A new probe cycle begins *)
        Lwt_condition.signal cond ();  (* Unblock sleep *)
        assert_equal ~msg:"#sleepl restart" ~printer:string_of_int 4 (List.length !sleepl);
        assert_equal ~msg:"#txlist restart" ~printer:string_of_int 2 (List.length !txlist);
        (* Verify the probe *)
        let (txaddr, txbuf) = List.hd !txlist in
        let (txip, txport) = txaddr in
        assert_equal ~printer:(fun s -> s) "224.0.0.251" (Ipaddr.V4.to_string txip);
        assert_equal ~printer:string_of_int 5353 txport;
        let packet = parse txbuf in
        (* Note that the hostname has not changed because that only occurs when we see an actual response *)
        let expected = "0000 Query:0 na:c:nr:rn 0 <qs:unique.local. <ANY_TYP|IN|QU>> <an:> <au:unique.local <IN,flush|120> [A (1.2.3.4)]> <ad:>" in
        assert_equal ~msg:"rr" ~printer:(fun s -> s) expected (to_string packet);
        (* Verify the sleep duration *)
        assert_equal ~msg:"restart sleep should be 250 ms" ~printer:string_of_float 0.25 (List.hd !sleepl);
        (* Ignore the rest of the cycle *)
      );

    "announce" >:: (fun test_ctxt ->
        let txlist = ref [] in
        let sleepl = ref [] in
        let module MockTransport = struct
          let alloc () = Cstruct.create 4096
          let write addr buf =
            txlist := (addr, buf) :: !txlist;
            Lwt.return ()
          let sleep t =
            sleepl := t :: !sleepl;
            Lwt.return ()
        end in
        let module Responder = Mdns_responder.Make(MockTransport) in
        let zonebuf = load_file "test_mdns.zone" in
        let responder = Responder.of_zonebufs [zonebuf] in
        (* Probe should do nothing because there are no unique records *)
(*         printf "before first_probe\n%!"; *)
        run_timeout (Responder.first_probe responder);
(*         printf "after first_probe\n%!"; *)
        assert_equal ~msg:"probe shouldn't send" ~printer:string_of_int 0 (List.length !txlist);
        assert_equal ~msg:"initial sleep" ~printer:string_of_int 1 (List.length !sleepl);
        (* Verify the sleep duration *)
        assert_range 0.0 0.25 (List.hd !sleepl);

        (* Announce *)
        run_timeout (Responder.announce responder ~repeat:3);

        (* Verify the first transmitted packet *)
        assert_equal ~printer:string_of_int 3 (List.length !txlist);
        assert_equal ~printer:string_of_int 3 (List.length !sleepl);
        let (txaddr, txbuf) = List.nth !txlist 2 in
        let (txip, txport) = txaddr in
        assert_equal ~printer:(fun s -> s) "224.0.0.251" (Ipaddr.V4.to_string txip);
        assert_equal ~printer:string_of_int 5353 txport;
        assert_equal ~msg:"first sleep should be 1 second" ~printer:string_of_float 1.0 (List.nth !sleepl 1);
        let packet = parse txbuf in
        assert_packet packet {qr=Response; opcode=Standard; aa=true; tc=false; rd=false; ra=false; rcode=NoError} 0 17 0 0;

        let sorted = packet.answers |> List.map rr_to_string |> List.sort String.compare in
        let expected_rrs = [
          "_foobar._tcp.local <IN|120> [SRV (0,0,9, fake1.local)]";
          "_snake._tcp.local <IN|120> [PTR (dugite._snake._tcp.local)]";
          "_snake._tcp.local <IN|120> [PTR (king brown._snake._tcp.local)]";
          "_snake._tcp.local <IN|120> [PTR (tiger._snake._tcp.local)]";
          "dugite._snake._tcp.local <IN|120> [SRV (0,0,33333, fake2.local)]";
          "dugite._snake._tcp.local <IN|120> [TXT (txtvers=1species=Pseudonaja affinis)]";
          "fake1.local <IN|4500> [A (127.0.0.94)]";
          "fake2.local <IN|4500> [A (127.0.0.95)]";
          "fake3.local <IN|4500> [A (127.0.0.96)]";
          "fake4.local <IN|4500> [CNAME (fake1.local)]";
          "king brown._snake._tcp.local <IN|120> [SRV (0,0,33333, fake3.local)]";
          "king brown._snake._tcp.local <IN|120> [TXT (txtvers=1species=Pseudechis australis)]";
          "laptop1.local <IN|120> [A (192.168.2.101)]";
          "mirage1.local <IN|120> [A (10.0.0.2)]";
          "router1.local <IN|120> [A (192.168.2.1)]";
          "tiger._snake._tcp.local <IN|120> [SRV (0,0,33333, fake1.local)]";
          "tiger._snake._tcp.local <IN|120> [TXT (txtvers=1species=Notechis scutatus)]";
        ] in
        List.iter2 (fun expected actual ->
            assert_equal ~msg:"rr" ~printer:(fun s -> s) expected actual
          ) expected_rrs sorted;

        (* The second packet should be exactly the same *)
        let (txaddr2, txbuf2) = List.nth !txlist 1 in
        assert_equal ~msg:"txaddr2" txaddr txaddr2;
        assert_equal ~msg:"txbuf2" txbuf txbuf2;
        assert_equal ~msg:"second sleep should be 2 seconds" ~printer:string_of_float 2.0 (List.nth !sleepl 0);

        (* The third packet should be exactly the same *)
        let (txaddr3, txbuf3) = List.nth !txlist 0 in
        assert_equal ~msg:"txaddr3" txaddr txaddr3;
        assert_equal ~msg:"txbuf3" txbuf txbuf3;
      );
  ]



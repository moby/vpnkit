[@@@warning "-27"]
open OUnit2
open Dns
open Packet
module Q = Query

let tests =
  "Query" >:::
  [
    "answer-dns" >:: (fun test_ctxt ->
        let trie = Test_trie.load_test_zone "test_dns.zone" in
        let name = Name.of_string "mail.d1.signpo.st." in
        let query =
          let detail = {
            qr=Query; opcode=Standard; aa=false;
            tc=false; rd=true; ra=false; rcode=NoError
          } in
          let q = {
            q_name=name;
            q_type=Q_A; q_class=Q_IN; q_unicast=Q_Normal;
          } in
          {
            id=0x930b; detail; questions=[q];
            answers=[]; authorities=[]; additionals=[];
          }
        in

        let answer = Q.answer ~dnssec:false ~mdns:false name Q_A trie in
        assert_equal NoError answer.Q.rcode;
        assert_equal true answer.Q.aa;
        assert_equal 1 (List.length answer.Q.answer);
        assert_equal ~printer:string_of_int 5 (List.length answer.Q.authority);
        assert_equal ~printer:string_of_int 1 (List.length answer.Q.additional);

        (* Verify the A record *)
        begin 
          let a = List.hd answer.Q.answer in
          assert_equal name a.name;
          assert_equal (Int32.of_int 172800) a.ttl;
          match a.rdata with
          | A ip ->
            assert_equal ~printer:(fun s -> s) "127.0.0.94" (Ipaddr.V4.to_string ip)
          | _ -> assert_failure "Not A"
        end;

        (* Verify the authority records *)
        (* Unfortunately the order of records is non-deterministic so we build a sorted list first *)
        let names = ["ns.isp.net"; "ns0.d1.signpo.st"; "ns2.isp.net"; "ns3.isp.net"; "ns4.isp.net"] in
        let rec get_ns_list rrs rest =
            begin
              match rrs with
              | [] -> rest;
              | ns::tl ->
                begin
                  assert_equal ~msg:"name" ~printer:(fun s -> s) "d1.signpo.st"
                               (Name.to_string ns.name);
                  assert_equal ~msg:"cls" RR_IN ns.cls;
                  assert_equal ~msg:"flush" false ns.flush;
                  assert_equal ~msg:"ttl" ~printer:Int32.to_string (Int32.of_int 604800) ns.ttl;
                  match ns.rdata with
                  | NS name ->
                    get_ns_list tl ((Name.to_string name) :: rest)
                  | _ -> assert_failure "Authority not A";
                end
            end in
        let ns_list = get_ns_list answer.Q.authority [] in
        let ns_sorted = List.sort String.compare ns_list in
        let rec dump_str_l l =
          match l with
          | [] -> ""
          | hd::tl -> hd ^ "; " ^ (dump_str_l tl) in
        assert_equal ~printer:dump_str_l names ns_sorted;

        (* Verify the additional record *)
        begin
          let ns = List.hd answer.Q.additional in
          assert_equal ~msg:"name" "ns0.d1.signpo.st" (Name.to_string ns.name);
          assert_equal ~msg:"cls" RR_IN ns.cls;
          assert_equal ~msg:"flush" false ns.flush;
          assert_equal ~msg:"ttl" (Int32.of_int 172800) ns.ttl;
          match ns.rdata with
          | A addr -> assert_equal ~msg:"A" ~printer:(fun s -> s) "127.0.0.94" (Ipaddr.V4.to_string addr)
          | _ -> assert_failure "Authority not A";
        end;

        let response = Q.response_of_answer query answer in
        assert_equal ~msg:"id" 0x930b response.id;
        assert_equal ~msg:"qr" Response response.detail.qr;
        assert_equal ~msg:"qu" query.questions response.questions;
        assert_equal ~msg:"an" answer.Q.answer response.answers;
        assert_equal ~msg:"au" answer.Q.authority response.authorities;
        assert_equal ~msg:"ad" answer.Q.additional response.additionals;
      );

    "answer-mdns-A" >:: (fun test_ctxt ->
        let trie = Test_trie.load_test_zone "test_mdns.zone" in
        let name = Name.of_string "fake1.local" in
        let query =
          let detail = {
            qr=Query; opcode=Standard; aa=false;
            tc=false; rd=true; ra=false; rcode=NoError
          } in
          let q = {
            q_name=name;
            q_type=Q_A; q_class=Q_IN; q_unicast=Q_Normal;
          } in
          {
            id=0x930b;  (* Should be ignored for mDNS *)
            detail; questions=[q];
            answers=[]; authorities=[]; additionals=[];
          }
        in

        let answer = Q.answer ~dnssec:false ~mdns:true name Q_A trie in
        assert_equal NoError answer.Q.rcode;
        assert_equal true answer.Q.aa;
        assert_equal 1 (List.length answer.Q.answer);
        assert_equal ~printer:string_of_int 0 (List.length answer.Q.authority);
        assert_equal ~printer:string_of_int 0 (List.length answer.Q.additional);

        (* Verify the A record *)
        begin 
          let a = List.hd answer.Q.answer in
          assert_equal name a.name;
          assert_equal (Int32.of_int 4500) a.ttl;
          match a.rdata with
          | A ip ->
            assert_equal ~printer:(fun s -> s) "127.0.0.94" (Ipaddr.V4.to_string ip)
          | _ -> assert_failure "Not A"
        end;

        let response = Q.response_of_answer ~mdns:true query answer in
        assert_equal ~msg:"id" ~printer:string_of_int 0 response.id;
        assert_equal ~msg:"qr" Response response.detail.qr;
        assert_equal ~msg:"#qu" ~printer:string_of_int 0 (List.length response.questions);
        assert_equal ~msg:"an" answer.Q.answer response.answers;
        assert_equal ~msg:"au" answer.Q.authority response.authorities;
        assert_equal ~msg:"ad" answer.Q.additional response.additionals;
      );

    "answer-mdns-PTR" >:: (fun test_ctxt ->
        let trie = Test_trie.load_test_zone "test_mdns.zone" in
        let name = Name.of_string "_snake._tcp.local" in
        let answer = Q.answer ~dnssec:false ~mdns:true name Q_PTR trie in
        assert_equal NoError answer.Q.rcode;
        assert_equal true answer.Q.aa;
        assert_equal 3 (List.length answer.Q.answer);
        assert_equal ~printer:string_of_int 0 (List.length answer.Q.authority);
        assert_equal ~printer:string_of_int 6 (List.length answer.Q.additional);

        (* Verify the PTR records *)
        (* Unfortunately the order of records is non-deterministic so we build a sorted list first *)
        let ptrl = ["dugite._snake._tcp.local"; "king brown._snake._tcp.local"; "tiger._snake._tcp.local"] in
        let rec get_ptr_list rrs rest =
            begin
              match rrs with
              | [] -> rest;
              | rr::tl ->
                begin
                  assert_equal ~msg:"name" ~printer:(fun s -> s)
                               "_snake._tcp.local" (Name.to_string rr.name);
                  assert_equal ~msg:"cls" RR_IN rr.cls;
                  assert_equal ~msg:"flush" false rr.flush;
                  assert_equal ~msg:"ttl" ~printer:Int32.to_string (Int32.of_int 120) rr.ttl;
                  match rr.rdata with
                  | PTR name ->
                    get_ptr_list tl ((Name.to_string name) :: rest)
                  | _ -> assert_failure "Not PTR";
                end
            end in
        let ptr_list = get_ptr_list answer.Q.answer [] in
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
              assert_equal ~printer:(fun s -> s) (List.assoc key srv_assoc)
                           (Name.to_string srv)
            | TXT txtl ->
              assert_equal 2 (List.length txtl);
              assert_equal "txtvers=1" (List.hd txtl);
              assert_equal ~printer:(fun s -> s) (List.assoc key txt_assoc) (List.nth txtl 1)
            | A ip ->
              assert_equal ~printer:(fun s -> s) (List.assoc key a_assoc) (Ipaddr.V4.to_string ip)
            | _ -> assert_failure "Not SRV, TXT or A"
          ) answer.Q.additional;
      );

    "answer_multiple-mdns" >:: (fun test_ctxt ->
        (* mDNS supports multiple questions in one query *)
        let trie = Test_trie.load_test_zone "test_mdns.zone" in
        let names = List.map Name.of_string ["fake1.local"; "fake2.local"] in
        (* Class IN or ANY is allowed *)
        let classes = [Q_IN; Q_ANY_CLS] in
        let questions = List.map2
            (fun q_name q_class -> {q_name; q_type=Q_A; q_class; q_unicast=Q_Normal})
            names classes
        in
        let answer = Q.answer_multiple ~dnssec:false ~mdns:true questions trie in
        assert_equal NoError answer.Q.rcode;
        assert_equal true answer.Q.aa;
        assert_equal 2 (List.length answer.Q.answer);
        assert_equal ~printer:string_of_int 0 (List.length answer.Q.authority);
        assert_equal ~printer:string_of_int 0 (List.length answer.Q.additional);

        (* Verify the A records (ignoring order) *)
        let a_assoc = List.combine names ["127.0.0.94"; "127.0.0.95"] in
        List.iter (fun rr ->
          assert_equal (Int32.of_int 4500) rr.ttl;
          match rr.rdata with
          | A ip ->
            assert_equal ~printer:(fun s -> s) (List.assoc rr.name a_assoc) (Ipaddr.V4.to_string ip)
          | _ -> assert_failure "Not A"
          ) answer.Q.answer
      );

    "answer_multiple-bad-class" >:: (fun test_ctxt ->
        let trie = Test_trie.load_test_zone "test_mdns.zone" in
        let names = List.map Name.of_string ["fake1.local"; "fake2.local"] in
        (* Q_CH, etc. are not supported *)
        let classes = [Q_CH; Q_HS] in
        let questions = List.map2
            (fun q_name q_class -> {q_name; q_type=Q_A; q_class; q_unicast=Q_Normal})
            names classes
        in
        let answer = Q.answer_multiple ~dnssec:false ~mdns:true questions trie in
        assert_equal NXDomain answer.Q.rcode;
        assert_equal true answer.Q.aa;
        assert_equal 0 (List.length answer.Q.answer);
        assert_equal ~printer:string_of_int 0 (List.length answer.Q.authority);
        assert_equal ~printer:string_of_int 0 (List.length answer.Q.additional);
      );

  ]


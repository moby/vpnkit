[@@@warning "-3-27"]
open OUnit2
open Printf

(* Adapted from ocaml-pcap/print/print.ml *)

[%%cstruct
type ethernet = {
    dst: uint8_t [@len 6];
    src: uint8_t [@len 6];
    ethertype: uint16_t;
  } [@@big_endian]
]

[%%cstruct
type ipv4 = {
    hlen_version: uint8_t;
    tos: uint8_t;
    len: uint16_t;
    id: uint16_t;
    off: uint16_t;
    ttl: uint8_t;
    proto: uint8_t;
    csum: uint16_t;
    src: uint8_t [@len 4];
    dst: uint8_t [@len 4];
  } [@@big_endian]
]

[%%cstruct
type udpv4 = {
    srouce_port: uint16_t;
    dest_port: uint16_t;
    length: uint16_t;
    checksum: uint16_t;
  } [@@big_endian]
]

let load_pcap path =
  let fd = Unix.(openfile path [O_RDONLY] 0) in
  let buf = Bigarray.(array1_of_genarray @@ Unix.map_file fd char c_layout false [|-1|]) in
  let buf = Cstruct.of_bigarray buf in
  let header, body = Cstruct.split buf Pcap.sizeof_pcap_header in
  match Pcap.detect header with
  | Some h ->
    Pcap.packets h body
  | None ->
    assert_failure "Not pcap format"

let load_packet path =
  match (load_pcap path) () with
  | Some (hdr, eth) ->
    assert_equal 0x0800 (get_ethernet_ethertype eth);
    let ip = Cstruct.shift eth sizeof_ethernet in
    let version = get_ipv4_hlen_version ip lsr 4 in
    assert_equal 4 version;
    assert_equal 17 (get_ipv4_proto ip);
    let udp = Cstruct.shift ip sizeof_ipv4 in
    Cstruct.shift udp sizeof_udpv4
  | None ->
    assert_failure "No packets"

let hexdump ibuf =
  let b = Buffer.create 16 in
  Cstruct.hexdump_to_buffer b ibuf ;
  Buffer.contents b

open Dns
open Packet

let tests =
  "Packet" >:::
  [
    "parse-dns-q-A" >:: (fun test_ctxt ->
        let raw = load_packet "dns-q-A.pcap" in
        let packet = parse raw in
        assert_equal ~msg:"id" 0x930b packet.id;
        assert_equal ~msg:"qr" Query packet.detail.qr;
        assert_equal ~msg:"opcode" Standard packet.detail.opcode;
        assert_equal ~msg:"aa" false packet.detail.aa;
        assert_equal ~msg:"tc" false packet.detail.tc;
        assert_equal ~msg:"rd" true packet.detail.rd;
        assert_equal ~msg:"ra" false packet.detail.ra;
        assert_equal ~msg:"rcode" NoError packet.detail.rcode;
        assert_equal ~msg:"#qu" 1 (List.length packet.questions);
        assert_equal ~msg:"#an" 0 (List.length packet.answers);
        assert_equal ~msg:"#au" 0 (List.length packet.authorities);
        assert_equal ~msg:"#ad" 0 (List.length packet.additionals);

        let q = List.hd packet.questions in
        assert_equal ~msg:"q_name" "www.google.com" (Name.to_string q.q_name);
        assert_equal ~msg:"q_type" Q_A q.q_type;
        assert_equal ~msg:"q_class" Q_IN q.q_class;
        assert_equal ~msg:"q_unicast" Q_Normal q.q_unicast;
    );

    "marshal-dns-q-A" >:: (fun test_ctxt ->
        let raw = load_packet "dns-q-A.pcap" in
        let packet =
          let detail = {
            qr=Query; opcode=Standard; aa=false;
            tc=false; rd=true; ra=false; rcode=NoError
          } in
          let q = make_question Q_A (Name.of_string "www.google.com") in
          {
            id=0x930b; detail; questions=[q];
            answers=[]; authorities=[]; additionals=[];
          } in
        let buf = marshal packet in
        assert_equal ~cmp:Cstruct.equal ~printer:hexdump raw buf
    );

    "parse-dns-r-A" >:: (fun test_ctxt ->
        let raw = load_packet "dns-r-A.pcap" in
        let packet = parse raw in
        assert_equal ~msg:"id" 0x930b packet.id;
        assert_equal ~msg:"qr" Response packet.detail.qr;
        assert_equal ~msg:"opcode" Standard packet.detail.opcode;
        assert_equal ~msg:"aa" false packet.detail.aa;
        assert_equal ~msg:"tc" false packet.detail.tc;
        assert_equal ~msg:"rd" true packet.detail.rd;
        assert_equal ~msg:"ra" true packet.detail.ra;
        assert_equal ~msg:"rcode" NoError packet.detail.rcode;
        assert_equal ~msg:"#qu" 1 (List.length packet.questions);
        assert_equal ~msg:"#an" 5 (List.length packet.answers);
        assert_equal ~msg:"#au" 0 (List.length packet.authorities);
        assert_equal ~msg:"#ad" 0 (List.length packet.additionals);

        let q = List.hd packet.questions in
        assert_equal ~msg:"q_name" "www.google.com" (Name.to_string q.q_name);
        assert_equal ~msg:"q_type" Q_A q.q_type;
        assert_equal ~msg:"q_class" Q_IN q.q_class;
        assert_equal ~msg:"q_unicast" Q_Normal q.q_unicast;

        let expected_fourth = [208; 211; 209; 212; 210] in
        List.iter2 (fun fourth a ->
            assert_equal ~msg:"name" "www.google.com" (Name.to_string a.name);
            assert_equal ~msg:"cls" RR_IN a.cls;
            assert_equal ~msg:"flush" false a.flush;
            assert_equal ~msg:"ttl" (Int32.of_int 220) a.ttl;
            let expected_addr = "74.125.237." ^ (string_of_int fourth) in
            match a.rdata with
            | A addr -> assert_equal ~msg:"A" ~printer:(fun s -> s) expected_addr (Ipaddr.V4.to_string addr)
            | _ -> assert_failure "RR type";
          ) expected_fourth packet.answers
    );

    "parse-dns-pointer-to-pointer" >:: (fun test_ctxt ->
        let raw = load_packet "dns-r-pointer-to-pointer.pcap" in
        let packet = parse raw in
        assert_equal ~msg:"#an" 3 (List.length packet.answers);

        packet.answers |> List.iter (fun a -> (
          assert_equal ~msg:"name" "amazonaws.com" (Name.to_string a.name)
        ));
    );

    "parse-dns-q-self-pointer" >:: (fun test_ctxt ->
      let raw = load_packet "dns-q-self-pointer.pcap" in
      assert_raises (Failure "Name.parse_pointer: Cannot dereference pointer to (12) at position (12)") (fun () -> parse raw)
    );

    "marshal-dns-r-A" >:: (fun test_ctxt ->
        let raw = load_packet "dns-r-A.pcap" in
        let packet =
          let detail = {
            qr=Response; opcode=Standard; aa=false;
            tc=false; rd=true; ra=true; rcode=NoError
          } in
          let q = make_question ~q_class:Q_IN ~q_unicast:Q_Normal Q_A (Name.of_string "www.google.com") in
          let answers = List.map (fun fourth -> {
                name=q.q_name; cls=RR_IN; flush=false; ttl=Int32.of_int 220;
                rdata=A (Ipaddr.V4.of_string_exn (sprintf "74.125.237.%d" fourth));
              }) [208; 211; 209; 212; 210]
          in
          {
            id=0x930b; detail; questions=[q];
            answers; authorities=[]; additionals=[];
          } in
        let buf = marshal packet in
        assert_equal ~cmp:Cstruct.equal ~printer:hexdump raw buf
    );

    "parse-mdns-q-A" >:: (fun test_ctxt ->
        let raw = load_packet "mdns-q-A.pcap" in
        let packet = parse raw in
        assert_equal ~msg:"id" 0 packet.id;
        assert_equal ~msg:"qr" Query packet.detail.qr;
        assert_equal ~msg:"opcode" Standard packet.detail.opcode;
        assert_equal ~msg:"aa" false packet.detail.aa;
        assert_equal ~msg:"tc" false packet.detail.tc;
        assert_equal ~msg:"rd" false packet.detail.rd;
        assert_equal ~msg:"ra" false packet.detail.ra;
        assert_equal ~msg:"rcode" NoError packet.detail.rcode;
        assert_equal ~msg:"#qu" 1 (List.length packet.questions);
        assert_equal ~msg:"#an" 0 (List.length packet.answers);
        assert_equal ~msg:"#au" 0 (List.length packet.authorities);
        assert_equal ~msg:"#ad" 0 (List.length packet.additionals);

        let q = List.hd packet.questions in
        assert_equal ~msg:"q_name" "cubieboard2.local" (Name.to_string q.q_name);
        assert_equal ~msg:"q_type" Q_A q.q_type;
        assert_equal ~msg:"q_class" Q_IN q.q_class;
        assert_equal ~msg:"q_unicast" Q_Normal q.q_unicast;
    );

    "marshal-mdns-q-A" >:: (fun test_ctxt ->
        let raw = load_packet "mdns-q-A.pcap" in
        let packet =
          let detail = {
            qr=Query; opcode=Standard; aa=false;
            tc=false; rd=false; ra=false; rcode=NoError
          } in
          let q = {
            q_name=(Name.of_string "cubieboard2.local");
            q_type=Q_A; q_class=Q_IN; q_unicast=Q_Normal;
          } in
          {
            id=0; detail; questions=[q];
            answers=[]; authorities=[]; additionals=[];
          } in
        let buf = marshal packet in
        assert_equal ~cmp:Cstruct.equal ~printer:hexdump raw buf
    );

    "parse-mdns-r-A" >:: (fun test_ctxt ->
        let raw = load_packet "mdns-r-A.pcap" in
        let packet = parse raw in
        assert_equal ~msg:"id" 0 packet.id;
        assert_equal ~msg:"qr" Response packet.detail.qr;
        assert_equal ~msg:"opcode" Standard packet.detail.opcode;
        assert_equal ~msg:"aa" true packet.detail.aa;
        assert_equal ~msg:"tc" false packet.detail.tc;
        assert_equal ~msg:"rd" false packet.detail.rd;
        assert_equal ~msg:"ra" false packet.detail.ra;
        assert_equal ~msg:"rcode" NoError packet.detail.rcode;
        assert_equal ~msg:"#qu" 0 (List.length packet.questions);
        assert_equal ~msg:"#an" 1 (List.length packet.answers);
        assert_equal ~msg:"#au" 0 (List.length packet.authorities);
        assert_equal ~msg:"#ad" 0 (List.length packet.additionals);

        let a = List.hd packet.answers in
        assert_equal ~msg:"name" "cubieboard2.local" (Name.to_string a.name);
        assert_equal ~msg:"cls" RR_IN a.cls;
        assert_equal ~msg:"flush" true a.flush;
        assert_equal ~msg:"ttl" (Int32.of_int 120) a.ttl;
        match a.rdata with
        | A addr -> assert_equal ~msg:"A" "192.168.2.106" (Ipaddr.V4.to_string addr)
        | _ -> assert_failure "RR type";
    );

    "marshal-mdns-r-A" >:: (fun test_ctxt ->
        let raw = load_packet "mdns-r-A.pcap" in
        let packet =
          let detail = {
            qr=Response; opcode=Standard; aa=true;
            tc=false; rd=false; ra=false; rcode=NoError
          } in
          let a = {
            name=(Name.of_string "cubieboard2.local"); cls=RR_IN; flush=true; ttl=Int32.of_int 120;
            rdata=A (Ipaddr.V4.of_string_exn "192.168.2.106");
          } in
          {
            id=0; detail; questions=[];
            answers=[a]; authorities=[]; additionals=[];
          } in
        let buf = marshal packet in
        assert_equal ~cmp:Cstruct.equal ~printer:hexdump raw buf
    );

    "q_unicast" >:: (fun test_ctxt ->
        (* Verify that q_unicast=Q_mDNS_Unicast can be marshalled and then parsed *)
        let packet =
          let detail = {
            qr=Query; opcode=Standard; aa=false;
            tc=false; rd=false; ra=false; rcode=NoError
          } in
          let q = {
            q_name=(Name.of_string "cubieboard2.local");
            q_type=Q_A; q_class=Q_IN; q_unicast=Q_mDNS_Unicast;
          } in
          {
            id=0; detail; questions=[q];
            answers=[]; authorities=[]; additionals=[];
          } in
        let buf = marshal packet in
        let parsed = parse buf in
        let q = List.hd parsed.questions in
        assert_equal Q_mDNS_Unicast q.q_unicast
      );

    "parse-mdns-r-SD" >:: (fun test_ctxt ->
        let raw = load_packet "mdns-r-SD.pcap" in
        let packet = parse raw in
        assert_equal ~msg:"#an" ~printer:string_of_int 4 (List.length packet.answers);
        let srv_name = "_udisks-ssh._tcp.local" in
        let srv_inst = "luke-xps." ^ srv_name in

        let a = List.nth packet.answers 0 in
        begin
          assert_equal ~msg:"TXT name" ~printer:(fun s -> s) srv_inst
                       (Name.to_string a.name);
          assert_equal ~msg:"TXT cls" RR_IN a.cls;
          assert_equal ~msg:"TXT flush" true a.flush;
          assert_equal ~msg:"TXT ttl" (Int32.of_int 4500) a.ttl;
          match a.rdata with
          | TXT l ->
            assert_equal ~msg:"TXT#" 1 (List.length l);
            assert_equal ~msg:"TXT" "" (List.hd l)
          | _ -> assert_failure "not TXT";
        end;

        let a = List.nth packet.answers 1 in
        begin
          assert_equal ~msg:"PTR name" ~printer:(fun s -> s) srv_name (Name.to_string a.name);
          assert_equal ~msg:"PTR cls" RR_IN a.cls;
          assert_equal ~msg:"PTR flush" false a.flush;
          assert_equal ~msg:"PTR ttl" (Int32.of_int 4500) a.ttl;
          match a.rdata with
          | PTR ptr -> assert_equal ~msg:"PTR" ~printer:(fun s -> s) srv_inst (Name.to_string ptr)
          | _ -> assert_failure "not PTR";
        end;

        let a = List.nth packet.answers 2 in
        begin
          assert_equal ~msg:"SRV name" ~printer:(fun s -> s) srv_inst (Name.to_string a.name);
          assert_equal ~msg:"SRV cls" RR_IN a.cls;
          assert_equal ~msg:"SRV flush" true a.flush;
          assert_equal ~msg:"SRV ttl" (Int32.of_int 120) a.ttl;
          match a.rdata with
          | SRV (priority, weight, port, srv) ->
            assert_equal 0 priority;
            assert_equal 0 weight;
            assert_equal 22 port;
            assert_equal ~msg:"SRV" ~printer:(fun s -> s) "luke-xps.local" (Name.to_string srv)
          | _ -> assert_failure "not SRV";
        end;

        let a = List.nth packet.answers 3 in
        begin
          assert_equal ~msg:"PTR2 name" ~printer:(fun s -> s) "_services._dns-sd._udp.local" (Name.to_string a.name);
          assert_equal ~msg:"PTR2 cls" RR_IN a.cls;
          assert_equal ~msg:"PTR2 flush" false a.flush;
          assert_equal ~msg:"PTR2 ttl" (Int32.of_int 4500) a.ttl;
          match a.rdata with
          | PTR ptr -> assert_equal ~msg:"PTR2" ~printer:(fun s -> s) srv_name (Name.to_string ptr)
          | _ -> assert_failure "not PTR2";
        end;
      );

    "parse-mdns-r-SD2" >:: (fun test_ctxt ->
        (* Compared to parse-mdns-r-SD above, this one is a better test of decompression *)
        (* TODO: this packet was generated by ocaml-dns so it may not be 100% realistic *)
        let raw = load_packet "mdns-r-SD2.pcap" in
        let packet = parse raw in
        let expected_str =
          "0000 Response:0 a:c:nr:rn 0 <qs:> \
           <an:\
           _snake._tcp.local <IN|120> [PTR (king brown._snake._tcp.local)],\
           _snake._tcp.local <IN|120> [PTR (tiger._snake._tcp.local)],\
           _snake._tcp.local <IN|120> [PTR (dugite._snake._tcp.local)]> <au:> <ad:\
           dugite._snake._tcp.local <IN|120> [SRV (0,0,33333, fake2.local)],\
           dugite._snake._tcp.local <IN|120> [TXT (txtvers=1species=Pseudonaja affinis)],\
           tiger._snake._tcp.local <IN|120> [SRV (0,0,33333, fake1.local)],\
           tiger._snake._tcp.local <IN|120> [TXT (txtvers=1species=Notechis scutatus)],\
           king brown._snake._tcp.local <IN|120> [SRV (0,0,33333, fake3.local)],\
           king brown._snake._tcp.local <IN|120> [TXT (txtvers=1species=Pseudechis australis)]\
           >" in
        assert_equal ~msg:"Packet.to_string" ~printer:(fun s -> s) expected_str (to_string packet)
      );
  ]

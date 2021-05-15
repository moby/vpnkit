open OUnit2
open Printf
open Lwt
open Dns.Packet
open Result

let run_timeout thread =
  Lwt_main.run (
    Lwt.pick [
      (Lwt_unix.sleep 1.0 >>= fun () -> return []);
      thread
    ])

module StubIpv4 = struct
  type error = Mirage_protocols.Ip.error

  type ethif = unit (*StubEthif.t*)
  type ipaddr = Ipaddr.V4.t
  type prefix = Ipaddr.V4.t
  type callback = src:ipaddr -> dst:ipaddr -> buffer -> unit Lwt.t

  type t = {
    ethif: ethif;
    mutable ip: Ipaddr.V4.t;
    mutable netmask: Ipaddr.V4.t;
    mutable gateways: Ipaddr.V4.t list;
  }

  let pp_error = Mirage_protocols.Ip.pp_error

  let input_arpv4 t buf = return_unit

  let id { ethif; _ } = ethif

  let allocate_frame t ~dst ~proto =
    let ethernet_frame = Cstruct.create 4096 in
    let len = 1500 in
    (ethernet_frame, len)

  let write t frame data =
    return @@ Ok ()

  let writev t ethernet_frame bufs =
    return @@ Ok ()

  let input t ~tcp ~udp ~default buf =
    return_unit

  let connect ethif =
    let ip = Ipaddr.V4.any in
    let netmask = Ipaddr.V4.any in
    let gateways = [] in
    let t = { ethif; ip; netmask; gateways } in
    return t

  let disconnect _ = return_unit

  let set_ip t ip =
    t.ip <- ip;
    return_unit

  let get_ip t = [t.ip]

  let set_ip_netmask t netmask =
    t.netmask <- netmask;
    return_unit

  let get_ip_netmasks t = [t.netmask]

  let set_ip_gateways t gateways =
    t.gateways <- gateways;
    return_unit

  let get_ip_gateways { gateways; _ } = gateways

  let checksum buf bufl =
    0

  let pseudoheader t ~dst ~proto len =
    Cstruct.create 0

  let src t ~dst:_ =
    t.ip

  type uipaddr = Ipaddr.t
  let to_uipaddr ip = Ipaddr.V4 ip
  let of_uipaddr = Ipaddr.to_v4

  let mtu _ = 1500
end


type write_call = {
  src_port : int;
  dst : Ipaddr.V4.t;
  dst_port : int;
  buf : Cstruct.t;
}

module MockUdpv4 = struct
  type ip = StubIpv4.t
  type ipaddr = Ipaddr.V4.t
  type ipinput = src:ipaddr -> dst:ipaddr -> buffer -> unit io
  type callback = src:Ipaddr.V4.t -> dst:Ipaddr.V4.t -> src_port:int -> Cstruct.t -> unit Lwt.t

  type error
  let pp_error _ (_:error) = assert false

  type t = {
    ip : ip;
    mutable writes : write_call list;
  }

  let id {ip} = ip

  let input ~listeners _t ~src ~dst buf = return_unit

  let writev ?src_port ~dst ~dst_port t bufs =
    let src_port = begin match src_port with
      | None -> assert_failure "src_port missing"
      | Some p -> p
    end in
    List.iter (fun buf -> t.writes <- { src_port; dst; dst_port; buf; } :: t.writes) bufs;
    return @@ Ok ()

  let write ?src_port ~dst ~dst_port t buf =
    writev ?src_port ~dst ~dst_port t [buf]

  let connect ip =
    return ({ ip; writes=[] })

  let disconnect _ = return_unit

  let pop_write t =
    if t.writes = [] then
      assert_failure "no write"
    else
      let hd = List.hd t.writes in
      t.writes <- List.tl t.writes;
      hd
end


module StubTcpv4 = struct
  type flow = unit (*Pcb.pcb*)
  type ip = StubIpv4.t
  type ipaddr = StubIpv4.ipaddr
  type ipinput = src:ipaddr -> dst:ipaddr -> buffer -> unit Lwt.t
  type t = ip (*Pcb.t*)
  type callback = flow -> unit Lwt.t

  type error = Mirage_protocols.Tcp.error
  type write_error = Mirage_protocols.Tcp.write_error
  let pp_error = Mirage_protocols.Tcp.pp_error
  let pp_write_error = Mirage_protocols.Tcp.pp_write_error

  let id t = t
  let dst t = (Ipaddr.V4.unspecified, 0)
  let read t = return (Ok `Eof)
  let write t view = return (Ok ())
  let writev t views = return (Ok ())
  let write_nodelay t view = return (Ok ())
  let writev_nodelay t views = return (Ok ())
  let close t = return_unit
  let create_connection tcp (daddr, dport) = return (Error `Refused)
  let input t ~listeners ~src ~dst buf = return_unit
  let connect ipv4 = return ipv4
  let disconnect _ = return_unit
end


module MockStack = struct
  type console = unit
  type 'a config = 'a Mirage_stack.stackv4_config
  type netif = unit
  type id = netif config
  type ipv4addr = Ipaddr.V4.t
  type tcpv4 = StubTcpv4.t
  type udpv4 = MockUdpv4.t
  type ipv4 = StubIpv4.t

  module UDPV4 = MockUdpv4
  module TCPV4 = StubTcpv4
  module IPV4  = StubIpv4

  type t = {
    id    : id;
    ipv4  : ipv4;
    udpv4 : udpv4;
    tcpv4 : tcpv4;
    udpv4_listeners: (int, UDPV4.callback) Hashtbl.t;
  }

  type error
  let pp_error _ (_:error) = assert false

  let id { id; _ } = id
  let tcpv4 { tcpv4; _ } = tcpv4
  let udpv4 { udpv4; _ } = udpv4
  let ipv4 { ipv4; _ } = ipv4

  let listen_udpv4 t ~port callback =
    Hashtbl.replace t.udpv4_listeners port callback

  let listen_tcpv4 t ~port callback = ()

  let configure t config = return_unit

  let udpv4_listeners t ~dst_port =
    try Some (Hashtbl.find t.udpv4_listeners dst_port)
    with Not_found -> None

  let listen t = return_unit

  let connect id =
    let { Mirage_stack.interface = netif; _ } = id in
    let udpv4_listeners = Hashtbl.create 7 in
    let ethif = () in
    StubIpv4.connect ethif >>= fun ipv4 ->
    MockUdpv4.connect ipv4 >>= fun udpv4 ->
    StubTcpv4.connect ipv4 >>= fun tcpv4 ->
      let t = { id; ipv4; tcpv4; udpv4;
                udpv4_listeners; } in
    let _ = listen t in
    return t

  let disconnect t = return_unit
end

let create_stack_lwt () =
  let interface = () in
  let config = {
    Mirage_stack.name = "mockstack";
    interface;
  } in
  MockStack.connect config

let create_stack () =
  Lwt_main.run (create_stack_lwt ())

module MockTime : Mirage_time.S = struct
  let sleep_ns _t = return_unit
end

let mdns_ip = Ipaddr.V4.of_string_exn "224.0.0.251"
let good_query_str = "valid.local"
let good_query_name = Dns.Name.of_string good_query_str
let good_response_ip = Ipaddr.V4.of_string_exn "10.0.0.3"
let good_detail = { qr=Response; opcode=Standard; aa=true; tc=false; rd=false; ra=false; rcode=NoError }
let good_answer = { name=good_query_name; cls=RR_IN; flush=true; ttl=120_l; rdata=A good_response_ip }

let bad_response_ip = Ipaddr.V4.of_string_exn "10.0.0.4"
let bad_answer = { name=good_query_name; cls=RR_IN; flush=true; ttl=120_l; rdata=A bad_response_ip }

let assert_ip ?msg expected ip =
  assert_equal ?msg ~printer:Ipaddr.V4.to_string expected ip

let simulate_response
    ?(from_ip=good_response_ip) ?(from_port=5353) ?(to_ip=mdns_ip)
    ?(id=0) ?(detail=good_detail)
    ?(answers=[bad_answer])
    stack
  =
  let response = { id; detail; questions=[]; answers; authorities=[]; additionals=[]; } in
  let buf = marshal response in
  let listener_thread = match MockStack.udpv4_listeners ~dst_port:5353 stack with
    | None -> assert_failure "missing listener"
    | Some listener -> listener ~src:from_ip ~dst:to_ip ~src_port:from_port buf
  in
  Lwt_main.run (
    Lwt.pick [
      Lwt_unix.sleep 1.0;
      listener_thread
    ])

let simulate_good_response stack = simulate_response ~answers:[good_answer] stack

let tests =
  "Mdns_resolver_mirage" >:::
  [
    "gethostbyname-fail" >:: (fun test_ctxt ->
        let stack = create_stack () in
        (* This mock Time module simulates a time-out *)
        let module T : Mirage_time.S = struct
          type 'a io = 'a Lwt.t
          let sleep_ns _t = return_unit
        end in
        let module R = Mdns_resolver_mirage.Make(T)(MockStack) in
        let r = R.create stack in
        let thread = R.gethostbyname r "fail.local" in
        try
          let _ = run_timeout thread in
          assert_failure "No exception raised"
        with
        | Dns.Protocol.Dns_resolve_error x -> ()
        | _ -> assert_failure "Unexpected exception raised"
      );

    "gethostbyname-success" >:: (fun test_ctxt ->
        let stack = create_stack () in
        let u = MockStack.udpv4 stack in
        let cond = Lwt_condition.create () in
        let module T : Mirage_time.S = struct
          type 'a io = 'a Lwt.t
          let sleep_ns t = Lwt_condition.wait cond
        end in
        let module R = Mdns_resolver_mirage.Make(T)(MockStack) in
        let r = R.create stack in

        (* Verify the query *)
        let thread = R.gethostbyname r good_query_str in
        let w = MockUdpv4.pop_write u in
        assert_equal ~printer:string_of_int 5353 w.src_port;
        assert_ip mdns_ip w.dst;
        assert_equal ~printer:string_of_int 5353 w.dst_port;
        let packet = parse w.buf in
        (* AA bit MUST be zero; RA bit MUST be zero; RD bit SHOULD be zero *)
        let expected = "0000 Query:0 na:c:nr:rn 0 <qs:valid.local. <A|IN>> <an:> <au:> <ad:>" in
        assert_equal ~msg:"packet" ~printer:(fun s -> s) expected (to_string packet);

        (* Simulate a response *)
        simulate_good_response stack;

        let result = run_timeout thread in
        assert_equal ~msg:"#result" ~printer:string_of_int 1 (List.length result);
        let result_ip = match List.hd result with
          | Ipaddr.V4 ip -> ip
          | _ -> assert_failure "not IPv4"
        in
        assert_equal ~msg:"result" ~printer:Ipaddr.V4.to_string good_response_ip result_ip
      );

    "response-validation" >:: (fun test_ctxt ->
        let stack = create_stack () in
        let u = MockStack.udpv4 stack in
        let cond = Lwt_condition.create () in
        let module T : Mirage_time.S = struct
          type 'a io = 'a Lwt.t
          let sleep_ns t = Lwt_condition.wait cond
        end in
        let module R = Mdns_resolver_mirage.Make(T)(MockStack) in
        let r = R.create stack in
        let thread = R.gethostbyname r good_query_str in
        let _ = MockUdpv4.pop_write u in

        (* TODO: should ignore responses that are not from the local link *)
        (* Simulate a response from the wrong source port *)
        simulate_response ~from_port:53 stack;
        (* Not a response *)
        simulate_response ~detail:{ good_detail with qr=Query } stack;
        (* Wrong opcode *)
        simulate_response ~detail:{ good_detail with opcode=Inverse } stack;
        (* Wrong rcode *)
        simulate_response ~detail:{ good_detail with rcode=NXDomain } stack;
        (* Wrong name *)
        simulate_response ~answers:[{ good_answer with name=Dns.Name.of_string "wrong.local" }] stack;
        (* Wrong class *)
        simulate_response ~answers:[{ good_answer with cls=RR_CS }] stack;
        (* Wrong RR type *)
        simulate_response ~answers:[{ good_answer with rdata=MX (111, good_query_name) }] stack;

        (* Verify that the query is re-sent in the event of a time-out *)
        Lwt_condition.signal cond ();
        let w2 = MockUdpv4.pop_write u in
        assert_equal ~printer:string_of_int 5353 w2.src_port;
        assert_ip mdns_ip w2.dst;
        assert_equal ~printer:string_of_int 5353 w2.dst_port;
        let query_packet = parse w2.buf in
        (* AA bit MUST be zero; RA bit MUST be zero; RD bit SHOULD be zero *)
        let expected = "0000 Query:0 na:c:nr:rn 0 <qs:valid.local. <A|IN>> <an:> <au:> <ad:>" in
        assert_equal ~msg:"query_packet" ~printer:(fun s -> s) expected (to_string query_packet);

        (* Simulate a valid response, but with a bad ID that should be ignored *)
        simulate_response ~id:1234 ~answers:[good_answer] stack;

        (* Verify that the result corresponds to the valid response *)
        let result = run_timeout thread in
        assert_equal ~msg:"#result" ~printer:string_of_int 1 (List.length result);
        let result_ip = match List.hd result with
          | Ipaddr.V4 ip -> ip
          | _ -> assert_failure "not IPv4"
        in
        assert_equal ~msg:"result" ~printer:Ipaddr.V4.to_string good_response_ip result_ip
      );

    "chain-local" >:: (fun test_ctxt ->
        let stack = create_stack () in
        let u = MockStack.udpv4 stack in
        let cond = Lwt_condition.create () in
        let module T : Mirage_time.S = struct
          type 'a io = 'a Lwt.t
          let sleep_ns t = Lwt_condition.wait cond
        end in
        let module DR = Dns_resolver_mirage.Make(T)(MockStack) in
        let module MR = Mdns_resolver_mirage.Make(T)(MockStack) in
        let module CR = Mdns_resolver_mirage.Chain(MR)(DR) in
        let r = CR.create stack in

        (* Verify the query *)
        let thread = CR.gethostbyname r good_query_str in
        let w = MockUdpv4.pop_write u in
        assert_equal ~printer:string_of_int 5353 w.src_port;
        assert_ip mdns_ip w.dst;
        assert_equal ~printer:string_of_int 5353 w.dst_port;
        let packet = parse w.buf in
        (* AA bit MUST be zero; RA bit MUST be zero; RD bit SHOULD be zero *)
        let expected = "0000 Query:0 na:c:nr:rn 0 <qs:valid.local. <A|IN>> <an:> <au:> <ad:>" in
        assert_equal ~msg:"packet" ~printer:(fun s -> s) expected (to_string packet);

        (* Simulate a response *)
        simulate_good_response stack;

        let result = run_timeout thread in
        assert_equal ~msg:"#result" ~printer:string_of_int 1 (List.length result);
        let result_ip = match List.hd result with
          | Ipaddr.V4 ip -> ip
          | _ -> assert_failure "not IPv4"
        in
        assert_equal ~msg:"result" ~printer:Ipaddr.V4.to_string good_response_ip result_ip
      );

    (* Awaiting https://github.com/mirage/ocaml-ipaddr/issues/53
    "chain-local-link" >:: (fun test_ctxt ->
        let stack = create_stack () in
        let u = MockStack.udpv4 stack in
        let cond = Lwt_condition.create () in
        let module T : Mirage_time.S = struct
          type 'a io = 'a Lwt.t
          let sleep t = Lwt_condition.wait cond
        end in
        let module DR = Dns_resolver_mirage.Make(T)(MockStack) in
        let module MR = Mdns_resolver_mirage.Chain(T)(MockStack)(DR) in
        let r = MR.create stack in

        (* Verify the query *)
        let ip = Ipaddr.V4.of_string_exn "169.254.111.222" in
        let thread = MR.gethostbyaddr r ip in
        let w = MockUdpv4.pop_write u in
        assert_equal ~printer:string_of_int 5353 w.src_port;
        assert_ip mdns_ip w.dst;
        assert_equal ~printer:string_of_int 5353 w.dst_port;
        Cstruct.hexdump w.buf;
        let packet = parse (Dns.Buf.of_cstruct w.buf) in
        (* AA bit MUST be zero; RA bit MUST be zero; RD bit SHOULD be zero *)
        let expected = "0000 Query:0 na:c:nr:rn 0 <qs:222.111.254.169.in-addr.arpa. <PTR|IN>> <an:> <au:> <ad:>" in
        assert_equal ~msg:"packet" ~printer:(fun s -> s) expected (to_string packet);

        (* Simulate a response *)
        let ptr_from = Dns.Name.of_string "222.111.254.169.in-addr.arpa" in
        let ptr_to = Dns.Name.of_string "reverse.local" in
        simulate_response ~answers:[{ name=ptr_from; cls=RR_IN; flush=true; ttl=120_l; rdata=PTR ptr_to }] stack;

        let result = run_timeout thread in
        assert_equal ~msg:"#result" ~printer:string_of_int 1 (List.length result);
        let result_str = List.hd result in
        assert_equal ~msg:"result" ~printer:(fun s -> s) "reverse.local" result_str
      );
    *)

  ]

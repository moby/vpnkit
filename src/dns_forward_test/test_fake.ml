module Error = Dns_forward.Error.Infix

let fresh_id =
  let next = ref 1000 in
  fun () ->
    let this = !next in
    next := !next mod 0xffff;
    this

let make_a_query name =
  let open Dns.Packet in
  let id = fresh_id () in
  let detail = { qr = Query; opcode = Standard; aa = true; tc = false; rd = true; ra = false; rcode = NoError } in
  let questions = [ make_question Q_A name ] in
  let answers = [] in
  let authorities = [] in
  let additionals = [] in
  let pkt = { id; detail; questions; answers; authorities; additionals } in
  marshal pkt

let fresh_port =
  let next = ref 0 in
  fun () ->
    let port = !next in
    incr next;
    port

(* One good one dead server should behave like the good server *)
let test_good_dead_server () =
  Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
  match Lwt_main.run begin
      let module Proto_server = Dns_forward.Rpc.Server.Make(Flow)(Dns_forward.Framing.Tcp(Flow)) in
      let module Proto_client = Dns_forward.Rpc.Client.Persistent.Make(Flow)(Dns_forward.Framing.Tcp(Flow)) in
      let module S = Server.Make(Proto_server) in
      let foo_public = "8.8.8.8" in
      (* a public server mapping 'foo' to a public ip *)
      let public_server = S.make [ "foo", Ipaddr.of_string_exn foo_public ] in
      let public_address =
        let port = fresh_port () in
        { Dns_forward.Config.Address.ip = Ipaddr.(V4 V4.localhost); port } in
      let open Error in
      S.serve ~address:public_address public_server
      >>= fun _ ->
      let bad_server = S.make ~delay:30. [] in
      let bad_address =
        let port = fresh_port () in
        { Dns_forward.Config.Address.ip = Ipaddr.(V4 V4.localhost); port } in
      S.serve ~address:bad_address bad_server
      >>= fun _ ->
      let module R = Dns_forward.Resolver.Make(Proto_client) in
      let open Dns_forward.Config in
      (* Forward to a good server and a bad server, both with timeouts. The request to
         the bad request should fail fast but the good server should be given up to
         the timeout to respond *)
      let servers = Server.Set.of_list [
          { Server.address = public_address; zones = Domain.Set.empty; timeout_ms = Some 1000; order = 0 };
          { Server.address = bad_address; zones = Domain.Set.empty; timeout_ms = Some 1000; order = 0 };
        ] in
      let config = { servers; search = []; assume_offline_after_drops = Some 1 } in
      let open Lwt.Infix in
      R.create ~gen_transaction_id:Random.int config
      >>= fun r ->
      let request = make_a_query (Dns.Name.of_string "foo") in
      let t = R.answer request r in
      (* First request will trigger the internal timeout and mark the bad server
         as offline. The sleep timeout here will only trigger if this fails. *)
      Fake_time_state.advance Duration.(of_sec 1);
      (* HACK: we want to let all threads run until they block but we don't have
         an API for that. This assumes that all computation will finish in 0.1s *)
      Lwt_unix.sleep 0.1 >>= fun () ->
      Fake_time_state.advance Duration.(of_sec 1);
      Lwt_unix.sleep 0.1 >>= fun () ->
      Lwt.pick [
        (Lwt_unix.sleep 1. >>= fun () -> Lwt.fail_with "test_good_dead_server: initial request had no response");
        t >>= fun _ -> Lwt.return_unit
      ]
      >>= fun () ->
      (* The bad server should be marked offline and no-one will wait for it *)
      Fake_time_state.reset ();
      Fake_time_state.advance Duration.(of_ms 500); (* avoid the timeouts winning the race with the actual result *)
      let request =
        R.answer request r
        >>= function
        | Ok reply ->
            let len = Cstruct.length reply in
            let buf = reply in
            begin match Dns.Protocol.Server.parse (Cstruct.sub buf 0 len) with
            | Some { Dns.Packet.answers = _ :: _ ; _ } -> Lwt.return_true
            | Some packet -> failwith ("test_good_dead_server bad response: " ^ (Dns.Packet.to_string packet))
            | None -> failwith "test_good_dead_server: failed to parse response"
            end
        | Error _ -> failwith "test_good_dead_server timeout: did the failure overtake the success?" in
      let timeout =
        Lwt_unix.sleep 5.
        >>= fun () ->
        Lwt.return false in
      Lwt.pick [ request; timeout ]
      >>= fun ok ->
      if not ok then failwith "test_good_dead_server hit timeout";
      R.destroy r
      >>= fun () ->
      Lwt.return (Ok ())
    end with
  | Ok () ->
      Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
  | Error (`Msg m) -> failwith m

let tests = [
  "Tolerate broken server", `Quick, test_good_dead_server;
]

let () =
  Logs.set_reporter (Logs_fmt.reporter ());
  Lwt.async_exception_hook := (fun exn ->
      Logs.err (fun f -> f "Lwt.async failure %s: %s"
                   (Printexc.to_string exn)
                   (Printexc.get_backtrace ())
               )
    );
  Random.self_init ();

  Alcotest.run "dns-forward-fake" [
    "Test infrastructure", tests 
  ]

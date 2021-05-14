
open OUnit2

let () =
  run_test_tt_main ("dns" >::: [
      Test_name.tests;
      Test_packet.tests;
      Test_trie.tests;
      Test_query.tests;
      (* Test_dns_resolver_unix.tests;
      Test_dns_server_mirage.tests;
      Test_mdns_responder.tests;
      Test_mdns_resolver_mirage.tests; *)
    ])


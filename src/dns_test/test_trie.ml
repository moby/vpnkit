[@@@warning "-27"]
open OUnit2
module H = Hashcons
open Dns
open Trie
open RR

let load_test_zone path =
  let ch = open_in path in
  let n = in_channel_length ch in
  let data = Bytes.create n in
  really_input ch data 0 n;
  close_in ch;
  let db = Dns.Loader.new_db () in
  let db = Dns.Zone.load ~db [] (Bytes.to_string data) in
  db.Dns.Loader.trie

let tests =
  "Trie" >:::
  [
    "found-dns" >:: (fun test_ctxt ->
        let trie = load_test_zone "test_dns.zone" in

        let name = Name.of_string "mail.d1.signpo.st." in
        match lookup (Name.to_key name) trie ~mdns:false with
        | `Found (sec, node, zonehead) -> (* Name has RRs, and we own it. *)
          assert_equal false sec;
          (* Verify the A record *)
          assert_equal name node.owner.H.node;
          assert_equal 1 (List.length node.rrsets);
          let a = List.hd node.rrsets in
          assert_equal (Int32.of_int 172800) a.ttl;
          begin 
            match a.rdata with
            | A ips ->
              assert_equal 1 (List.length ips);
              assert_equal "127.0.0.94" (ips |> List.hd |> Ipaddr.V4.to_string)
            | _ -> assert_failure "Not A"
          end;

          (* Verify the SOA record *)
          assert_equal "d1.signpo.st" (Name.to_string zonehead.owner.H.node);
          assert_equal ~printer:string_of_int 3 (List.length zonehead.rrsets);
          let soa = List.nth zonehead.rrsets 1 in
          assert_equal (Int32.of_int 604800) soa.ttl;
          begin
            match soa.rdata with
            | SOA soas ->
              assert_equal 1 (List.length soas);
              let (master, rp, serial, refresh, retry, expiry, min) = List.hd soas in
              assert_equal "ns0.d1.signpo.st" (Name.to_string master.owner.H.node);
              (* Warning: the first dot is part of the first label *)
              assert_equal "john.doe.d1.signpo.st" (Name.to_string rp.owner.H.node);
              assert_equal ~msg:"refresh" (Int32.of_int 3600) refresh;
              assert_equal ~msg:"retry" (Int32.of_int 1800) retry;
              assert_equal ~msg:"expiry" (Int32.of_int 3024000) expiry;
              assert_equal ~msg:"min" (Int32.of_int 1800) min;
            | _ -> assert_failure "Not SOA"
          end
        | _ -> assert_failure "Not found"
      );

    "found-mdns" >:: (fun test_ctxt ->
        let trie = load_test_zone "test_mdns.zone" in

        let name = Name.of_string "fake1.local." in
        match lookup (Name.to_key name) trie ~mdns:true with
        | `Found (sec, node, zonehead) -> (* Name has RRs, and we own it. *)
          begin 
            assert_equal false sec;
            assert_equal name node.owner.H.node;
            assert_equal 1 (List.length node.rrsets);
            let a = List.hd node.rrsets in
            assert_equal (Int32.of_int 4500) a.ttl;
            match a.rdata with
            | A ips ->
              assert_equal 1 (List.length ips);
              assert_equal "127.0.0.94" (ips |> List.hd |> Ipaddr.V4.to_string)
            | _ -> assert_failure "Not A"
            (* zonehead is not used for mDNS *)
          end
        | _ -> assert_failure "Not found";
      );

    "nxdomain-dns" >:: (fun test_ctxt ->
        let trie = load_test_zone "test_dns.zone" in

        let name = Name.of_string "bigfoot.d1.signpo.st." in
        match lookup (Name.to_key name) trie ~mdns:false with
        | `NXDomain (zonehead) ->         (* Name doesn't exist. *)
          (* Verify part of the SOA record *)
          assert_equal "d1.signpo.st" (Name.to_string zonehead.owner.H.node);
          assert_equal ~printer:string_of_int 3 (List.length zonehead.rrsets);
          let soa = List.nth zonehead.rrsets 1 in
          assert_equal (Int32.of_int 604800) soa.ttl;
        | _ -> assert_failure "Not NXDomain"
      );

    "nxdomain-mdns" >:: (fun test_ctxt ->
        let trie = load_test_zone "test_mdns.zone" in

        let names = ["bigfoot.local."; "bigfoot"; "bigfoot.d1.signpo.st."] in
        List.iter (fun name ->
            match lookup (name |> Name.of_string |> Name.to_key) trie ~mdns:true with
            | `NXDomain (zonehead) ->         (* Name doesn't exist. *)
              (* Note that NXDomain is only used internally and not transmitted for mDNS *)
              (* zonehead is not used for mDNS *)
              ()
            | _ -> assert_failure ("Not NXDomain: " ^ name)
          ) names
      );

    "delegated" >:: (fun test_ctxt ->
        let trie = load_test_zone "test_dns.zone" in

        let name = Name.of_string "cam.ac.uk." in
        match lookup (Name.to_key name) trie ~mdns:false with
        | `Delegated (sec, cutpoint) ->   (* Name is delegated. *)
          (* Verify the NS record *)
          assert_equal false sec;
          assert_equal "uk" (Name.to_string cutpoint.owner.H.node);
          assert_equal ~printer:string_of_int 1 (List.length cutpoint.rrsets);
          let ns = List.hd cutpoint.rrsets in
          assert_equal (Int32.of_int 1000) ns.ttl;
          begin
            match ns.rdata with
            | NS l ->
              assert_equal 1 (List.length l);
              let node = List.hd l in
              assert_equal "ns1.nic.uk" (Name.to_string node.owner.H.node);
            | _ -> assert_failure "Not NS"
          end
        | _ -> assert_failure "Not Delegated"
      );

    "noerror" >:: (fun test_ctxt ->
        let trie = load_test_zone "test_dns.zone" in

        let name = Name.of_string "one.d1.signpo.st." in
        match lookup (Name.to_key name) trie ~mdns:false with
        | `NoError (zonehead) ->          (* Name "exists", but has no RRs. *)
          (* Verify part of the SOA record *)
          assert_equal "d1.signpo.st" (Name.to_string zonehead.owner.H.node);
          assert_equal ~printer:string_of_int 3 (List.length zonehead.rrsets);
          let soa = List.nth zonehead.rrsets 1 in
          assert_equal (Int32.of_int 604800) soa.ttl;
        | _ -> assert_failure "Not Delegated"
      );

  ]


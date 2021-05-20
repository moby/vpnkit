
open OUnit2
open Lwt

let tests =
  "Dns_resolver_unix" >:::
  [
    "fd-leak-test" >:: (fun _ ->
      (* From https://github.com/mirage/ocaml-dns/issues/15 *)

      let rec loop k m resolver =
        if k <= m
        then (Dns_resolver_unix.gethostbyname resolver "www.example.com"
              >>= fun _packet ->
              loop (k + 1) m resolver)
        else return ()
      in

      (* sequential resolution of 1025 names to test for fd leaks *)
      Lwt_main.run (Dns_resolver_unix.create () >>= loop 0 (1 lsl 10 + 1))
    );

    "resolution-error" >:: (fun _ ->
      (* Failed resolution of one name to test for correct error *)
      let config = `Static ([Ipaddr.of_string_exn "127.0.0.2", 53],[]) in
      Lwt_main.run begin
        Dns_resolver_unix.create ~config ()
        >>= fun resolver ->
        catch (fun () ->
          let open Dns.Packet in
          let name = Dns.Name.of_string "www.example.com" in
          Dns_resolver_unix.resolve resolver Q_IN Q_MX name
          >|= fun _ -> None
        ) (fun exn -> return (Some exn))
        >>= Dns.(function
          | Some (Protocol.Dns_resolve_error [Protocol.Dns_resolve_timeout]) ->
            return ()
          | None ->
            assert_failure "resolution error test: failed with no error\n"
          | Some (Protocol.Dns_resolve_error exns) ->
            let open Buffer in
            let b = create 128 in
            add_string b "resolution error test: failed with bad errors:\n";
            List.iter (fun exn ->
              add_string b (Printexc.to_string exn ^ "\n")
            ) exns;
            add_string b "\n";
            assert_failure (contents b)
          | Some exn ->
            let open Buffer in
            let b = create 128 in
            add_string b "resolution error test: failed with unexpected error:\n";
            add_string b (Printexc.to_string exn ^ "\n\n");
            assert_failure (contents b)
        )
      end
    )
  ]

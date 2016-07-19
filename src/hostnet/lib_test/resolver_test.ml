

let examples = [
  "10.0.0.2\n1.2.3.4#54", [
    Ipaddr.V4 (Ipaddr.V4.of_string_exn "10.0.0.2"), 53;
    Ipaddr.V4 (Ipaddr.V4.of_string_exn "1.2.3.4"), 54;
  ];
  "10.0.0.2\n", [
    Ipaddr.V4 (Ipaddr.V4.of_string_exn "10.0.0.2"), 53;
  ];
]

let test_one txt expected () =
  match Hostnet.Resolver.parse_resolvers txt with
  | None ->
    failwith "None"
  | Some x ->
    List.iter (fun ((a, a_port), (b, b_port)) ->
      if Ipaddr.compare a b <> 0 then failwith "IP doesn't match";
      if a_port <> b_port then failwith "port doesn't match"
    ) (List.combine expected x)

let tests = List.map (fun (txt, expected) ->
  "DNS " ^ (String.escaped txt), `Quick, test_one txt expected
) examples

let suite = [
  "Resolver parsing", tests;
]

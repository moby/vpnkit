open Hostnet.Resolver

let examples = [
  "nameserver 10.0.0.2\nnameserver 1.2.3.4#54\nsearch a b c",
  { resolvers = [
    Ipaddr.V4 (Ipaddr.V4.of_string_exn "10.0.0.2"), 53;
    Ipaddr.V4 (Ipaddr.V4.of_string_exn "1.2.3.4"), 54;
  ]; search = [ "a"; "b"; "c" ] };
  "nameserver 10.0.0.2\n",
  { resolvers = [
    Ipaddr.V4 (Ipaddr.V4.of_string_exn "10.0.0.2"), 53;
  ]; search = [] };
]

let test_one txt expected () =
  match Hostnet.Resolver.parse_resolvers txt with
  | None ->
    failwith "None"
  | Some x ->
    List.iter (fun ((a, a_port), (b, b_port)) ->
      if Ipaddr.compare a b <> 0 then failwith "IP doesn't match";
      if a_port <> b_port then failwith "port doesn't match"
    ) (List.combine expected.resolvers x.resolvers);
    List.iter (fun (a_domain, b_domain) ->
      if a_domain <> b_domain then failwith "Search domain doesn't match";
    ) (List.combine expected.search x.search)

let tests = List.map (fun (txt, expected) ->
  "DNS " ^ (String.escaped txt), `Quick, test_one txt expected
) examples

let suite = [
  "Resolver parsing", tests;
]

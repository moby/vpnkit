let examples = [
  "Windows-style", String.concat "\n" [
    "# For example:";
    "#";
    "1.2.3.4     www.docker.com     # web server";
    "4.5.6.7     staging.docker.com # staging web server";
  ], [
    "www.docker.com", Ipaddr.of_string_exn "1.2.3.4";
    "staging.docker.com", Ipaddr.of_string_exn "4.5.6.7";
  ];
  "Mac-style", String.concat "\n" [
    "##";
    "# Host Database";
    "#";
    "# localhost is used to configure the loopback interface";
    "# when the system is booting.  Do not change this entry.";
    "##";
    "127.0.0.1      	localhost mylocalhostalias";
    "255.255.255.255	broadcasthost";
    "::1             localhost";
  ], [
    "mylocalhostalias", Ipaddr.V4 Ipaddr.V4.localhost;
    "localhost", Ipaddr.V4 Ipaddr.V4.localhost;
    "broadcasthost", Ipaddr.of_string_exn "255.255.255.255";
    "localhost", Ipaddr.of_string_exn "::1";
  ]
]

let test_one txt expected () =
  let x = Hosts.of_string txt in
  let expected' = List.length expected in
  let x' = List.length x in
  if expected' <> x'
  then
    Fmt.kstr failwith "Expected %d hosts in /etc/hosts but found %d"
      expected' x';
  List.iter (fun ((a_name, a_ip), (b_name, b_ip)) ->
      if Ipaddr.compare a_ip b_ip <> 0 then failwith "IP doesn't match";
      if a_name <> b_name then failwith "name doesn't match"
    ) (List.combine expected x)

let tests = List.map (fun (name, txt, expected) ->
    "hosts " ^ name, [ "", `Quick, test_one txt expected ]
  ) examples

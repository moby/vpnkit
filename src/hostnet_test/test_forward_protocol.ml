(* Test the protocol used by vpnkit-forwarder *)

open Forwarding__Frame

let inputs = [
  "open_dedicated_connection", {
    command = Open(Dedicated, Destination.({proto = `Tcp; ip = Ipaddr.V4 Ipaddr.V4.localhost; port = 8080}));
    id = 4l;
  };
  "open_multiplexed_connection", {
    command = Open(Multiplexed, Destination.({proto = `Udp; ip = Ipaddr.V6 Ipaddr.V6.localhost; port = 8080}));
    id = 5l;
  };
  "close", {
    command = Close;
    id = 6l;
  };
  "shutdown", {
    command = Shutdown;
    id = 7l;
  };
  "data", {
    command = Data 128l;
    id = 8l;
  };
  "window", {
    command = Window 8888888L;
    id = 9l;
  };
]

let output_dir = Filename.(concat (dirname Sys.argv.(0)) "test_inputs")

(* Regenerate test output files. This is only needed when changing the protocol and
   updating the tests. *)
let test_print name frame () =
  let buf = write frame (Cstruct.create (sizeof frame)) in
  let oc = open_out (Filename.concat output_dir (name ^ ".bin")) in
  output_string oc (Cstruct.to_string buf);
  close_out oc

let test_print_parse frame () =
  let buf = write frame (Cstruct.create (sizeof frame)) in
  let frame' = read buf in
  assert (frame = frame')

let test_parse name frame () =
  let ic = open_in (Filename.concat output_dir (name ^ ".bin")) in
  let b = Bytes.create 100 in (* more than big enough *)
  let n = input ic b 0 100 in
  close_in ic;
  let buf = Cstruct.create n in
  Cstruct.blit_from_bytes b 0 buf 0 n;
  let frame' = read buf in
  assert (frame = frame')

let suite = List.map (fun (name, frame) ->
  name, [
    (* "check that we can print", `Quick, test_print name frame; *)
    "check that we can parse what we print", `Quick, test_print_parse frame;
    "check that we can parse files on disk", `Quick, test_parse name frame
  ]
) inputs
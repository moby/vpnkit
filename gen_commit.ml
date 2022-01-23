(* Generate the artifact COMMIT which stores the source commit sha *)
let usage_msg = "gen_commit -o <output>"
let output_file = ref "COMMIT"

let speclist =
  [("-o", Arg.Set_string output_file, "Set output file name")]

let other_arg name = Printf.fprintf stderr "ignoring unexpected argument %s" name

let () =
  Arg.parse speclist other_arg usage_msg;
  (* Avoid using Unix shell features like redirection *)
  let ic = Unix.open_process_in "git rev-parse HEAD" in
  let commit = input_line ic in
  let oc = open_out !output_file in
  output_string oc commit;
  close_out oc;
  close_in ic

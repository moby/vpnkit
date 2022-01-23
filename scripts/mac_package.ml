(* Generate the Mac .tgz *)
let usage_msg = "mac_package -in <vpnkit.exe> -out <output.tgz>"
let output_file = ref "vpnkit.tgz"
let input_file = ref "vpnkit.exe"

let speclist =
  [("-out", Arg.Set_string output_file, "Set output file name");
   ("-in", Arg.Set_string input_file, "Set input file name")]

let run cmd = match Unix.system cmd with
  | Unix.WEXITED 0 -> ()
  | Unix.WEXITED n -> failwith (Printf.sprintf "%s: %d" cmd n)
  | _ -> failwith (Printf.sprintf "%s: unexpected signal" cmd)

let () =
  Arg.parse speclist ignore usage_msg;
  let root = "package" in
  List.iter run [
    "mkdir -p " ^ (root ^ "/Contents/Resources/bin");
    "cp " ^ !input_file ^ " " ^ root ^ "/Contents/Resources/bin/vpnkit";
    "dylibbundler -od -b -x " ^ root ^ "/Contents/Resources/bin/vpnkit -d " ^ root ^ "/Contents/Resources/lib -p @executable_path/../lib";
    "tar -C " ^ root ^ " -cvzf " ^ !output_file ^ " Contents";
  ]

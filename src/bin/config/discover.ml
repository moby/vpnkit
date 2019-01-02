open Sexplib.Std

let flags () =
  let ic = Unix.open_process_in "/bin/uname" in
  let line = input_line ic in
  close_in ic;
  match line with
  | "Linux" ->
    [ "-ccopt"; "-static" ]
  | _ ->
    []

let _ =
  let txt = Sexplib.Sexp.(to_string (List (List.map (fun flag -> Atom flag) (flags ())))) in
  let oc = open_out "flags.sexp" in
  output_string oc txt;
  close_out oc

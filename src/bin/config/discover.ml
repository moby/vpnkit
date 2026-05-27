let os_type () =
  match Sys.os_type with
  | "Unix" ->
    (* We want to differentiate between Linux and Darwin/macOS *)
    let ic = Unix.open_process_in "uname" in
    let line = input_line ic in
    let _ = Unix.close_process_in ic in
    line
  | x -> x

let static_build () =
  (* if DYNAMIC is set (to anything) its not a static build *)
  match Unix.getenv "DYNAMIC" with
  | _ -> false
  | exception Not_found -> true

let flags () =
  match os_type () with
  | "Linux" -> (
    match static_build () with
    | true -> [ "-ccopt"; "-static" ]
    | false -> [])
  | _ ->
    []

let _ =
  let txt = Sexplib.Sexp.(to_string (List (List.map (fun flag -> Atom flag) (flags ())))) in
  let oc = open_out "flags.sexp" in
  output_string oc txt;
  close_out oc

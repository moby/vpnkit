let src =
  let src =
    Logs.Src.create "Connection_limit" ~doc:"Track and limit open connections"
  in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

(* Ensure the table is safe to access from both the Luv event loop and the Lwt event loop. *)
let m = Mutex.create ()

let with_mutex m f =
  Mutex.lock m;
  try
    let result = f () in
    Mutex.unlock m;
    result
  with e ->
    Mutex.unlock m;
    raise e

let max = ref None

let next =
  let idx = ref 0 in
  fun () ->
    let next = !idx in
    incr idx;
    next

let table = Hashtbl.create 511

let set_max x =
  with_mutex m (fun () ->
      (match x with
      | None -> Log.info (fun f -> f "Removed connection limit")
      | Some limit ->
          Log.info (fun f -> f "Updated connection limit to %d" limit));
      max := x)

let get_num_connections () = with_mutex m (fun () -> Hashtbl.length table)

let connections () =
  with_mutex m (fun () ->
      let xs = Hashtbl.fold (fun _ c acc -> c :: acc) table [] in
      Vfs.File.ro_of_string (String.concat "\n" xs))

let register_no_limit description =
  with_mutex m (fun () ->
      let idx = next () in
      Hashtbl.replace table idx description;
      idx)

let register =
  with_mutex m (fun () ->
      let last_error_log = ref 0. in
      fun description ->
        match !max with
        | Some m when Hashtbl.length table >= m ->
            let now = Unix.gettimeofday () in
            if now -. !last_error_log > 30. then (
              (* Avoid hammering the logging system *)
              Log.warn (fun f ->
                  f "Exceeded maximum number of forwarded connections (%d)" m);
              last_error_log := now);
            Error (`Msg "too many open connections")
        | _ -> Ok (register_no_limit description))

let deregister idx =
  with_mutex m (fun () ->
      if not (Hashtbl.mem table idx) then
        Log.warn (fun f -> f "Deregistered connection %d more than once" idx);
      Hashtbl.remove table idx)

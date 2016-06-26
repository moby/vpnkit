
let read_file path =
  let open Lwt.Infix in
  Lwt.catch
    (fun () ->
      Lwt_unix.openfile path [ Lwt_unix.O_RDONLY ] 0
      >>= fun fd ->
      let buffer = Buffer.create 128 in
      let frag = Bytes.make 1024 ' ' in
      Lwt.finalize
        (fun () ->
          let rec loop () =
            Lwt_unix.read fd frag 0 (Bytes.length frag)
            >>= function
            | 0 ->
              Lwt.return (`Ok (Buffer.contents buffer))
            | n ->
              Buffer.add_substring buffer frag 0 n;
              loop () in
          loop ()
        ) (fun () ->
          Lwt_unix.close fd
        )
    ) (fun e ->
      Lwt.return (`Error (`Msg (Printf.sprintf "reading %s: %s" path (Printexc.to_string e))))
    )

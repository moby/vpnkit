let src =
  let src = Logs.Src.create "DNS config" ~doc:"monitor host DNS configuration" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

open Lwt
open Dns.Resolvconf

let resolv_conf = "/etc/resolv.conf"

module Files = Hostnet.Files

let get () =
  Files.read_file resolv_conf
  >>= function
  | `Error (`Msg m) ->
    Log.err (fun f -> f "Error reading %s: %s" resolv_conf m);
    Lwt.return []
  | `Ok txt ->
    let lines = Astring.String.cuts ~sep:"\n" txt in
    let config = List.rev @@ List.fold_left (fun acc x ->
      match map_line x with
      | None -> acc
      | Some x ->
        begin
          try
            KeywordValue.of_string x :: acc
          with
          | _ -> acc
        end
    ) [] lines in
    Lwt.return (all_servers config)


let parse_resolvers txt =
  let open Astring in
  try
    let lines = String.cuts ~sep:"\n" txt in
    Some (List.rev (List.fold_left
      (fun acc line ->
        let line = String.trim line in
        if line = "" then acc
        else if String.cut ~sep:"::" line <> None then begin
          (* IPv6 *)
          let host = Ipaddr.V6.of_string_exn line in
          (Ipaddr.V6 host, 53) :: acc
        end else match String.cut ~sep:"#" line with
          | Some (host, port) ->
            (* IPv4 with non-standard port *)
            let host = Ipaddr.V4.of_string_exn host in
            let port = int_of_string port in
            (Ipaddr.V4 host, port) :: acc
          | None ->
            (* IPv4 with standard port *)
            let host = Ipaddr.V4.of_string_exn line in
            (Ipaddr.V4 host, 53) :: acc
      ) [] lines))
  with _ -> None

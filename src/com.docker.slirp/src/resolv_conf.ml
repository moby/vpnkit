let src =
  let src = Logs.Src.create "DNS config" ~doc:"monitor host DNS configuration" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

open Lwt
open Hostnet
open Dns.Resolvconf

let resolv_conf = "/etc/resolv.conf"

module Make(Files: Sig.FILES) = struct

  let default_dns = ref []

  let set_default_dns dns = default_dns := dns

  (* The current_dns settings are the ones we're using right now. Overrides
     via the database will be made here by `set` *)
  let current_dns = ref { Resolver.resolvers = !default_dns; search = [] }

  let set x = match x.Resolver.resolvers with
    | _ :: _ as dns ->
      Log.info (fun f -> f "using DNS forwarders on %s"
                   (String.concat "; " (List.map (fun (ip, port) -> Ipaddr.to_string ip ^ "#" ^ (string_of_int port)) dns))
               );
      current_dns := x
    | [] ->
      Log.info (fun f -> f "using default DNS on %s"
                   (String.concat "; " (List.map (fun (ip, port) -> Ipaddr.to_string ip ^ "#" ^ (string_of_int port)) !default_dns))
               );
      current_dns := { Resolver.resolvers = !default_dns; search = [] }

  let all_ipv4_servers config =
     all_servers config |>
     List.filter (fun (ip,_) -> match ip with Ipaddr.V4 _ -> true |_ -> false)

  let get () =
    match !current_dns.Resolver.resolvers with
    | _ :: _ -> Lwt.return !current_dns
    | [] ->
      Files.read_file resolv_conf
      >>= function
      | `Error (`Msg m) ->
        Log.err (fun f -> f "Error reading %s: %s" resolv_conf m);
        Lwt.return { Resolver.resolvers = !default_dns; search = [] }
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
        Lwt.return ({ Resolver.resolvers = all_ipv4_servers config; search = []})

end

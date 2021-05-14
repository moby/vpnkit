(*
 * Copyright (C) 2016 David Scott <dave@recoil.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)

module Address = struct
  module M = struct
    type t = {
      ip: Ipaddr.t;
      port: int;
    }

    let compare a b =
      let ip = Ipaddr.compare a.ip b.ip in
      if ip <> 0 then ip else Stdlib.compare a.port b.port
  end
  include M
  let to_string { ip; port } = Printf.sprintf "%s:%d" (Ipaddr.to_string ip) port
  module Set = Set.Make(M)
  module Map = Map.Make(M)
end

module Domain = struct
  module M = struct
    type t = string list
    let compare (a: t) (b: t) = Stdlib.compare a b
  end
  include M
  module Set = Set.Make(M)
  module Map = Map.Make(M)
  let to_string = String.concat "."
end

module Server = struct
  module M = struct
    type t = {
      zones: Domain.Set.t;
      address: Address.t;
      timeout_ms: int option;
      order: int;
    }

    let compare (a: t) (b: t) =
      let zones = Domain.Set.compare a.zones b.zones in
      let address = Address.compare a.address b.address in
      let order = Stdlib.compare a.order b.order in
      let timeout_ms = Stdlib.compare a.timeout_ms b.timeout_ms in
      if address <> 0 then address
      else if zones <> 0 then zones
      else if order <> 0 then order
      else timeout_ms
  end
  include M
  module Set = Set.Make(M)
  module Map = Map.Make(M)
end

type t = {
  servers: Server.Set.t;
  search: string list;
  assume_offline_after_drops: int option;
}

let compare a b =
  let servers = Server.Set.compare a.servers b.servers in
  if servers <> 0 then servers else Stdlib.compare a.search b.search

let nameserver_prefix = "nameserver "
let search_prefix = "search "
let zone_prefix = "zone "
let timeout_prefix = "timeout "
let order_prefix = "order "
let assume_offline_after_prefix = "assume-offline-after "

let of_string txt =
  let open Astring in
  let whitespace = function ' ' | '\r' | '\n' | '\t' -> true | _ -> false in
  try
    (* Chop into lines *)
    String.cuts ~sep:"\n" txt
    |> List.map (String.trim ?drop:None)
    |> List.filter (fun x -> x <> "")
    |> List.fold_left
      (fun acc line ->
         if String.is_prefix ~affix:nameserver_prefix line then begin
           let line = String.with_range ~first:(String.length nameserver_prefix) line in
           if String.cut ~sep:"::" line <> None then begin
             (* IPv6 *)
             let host = Ipaddr.V6.of_string_exn line in
             (`Nameserver (Ipaddr.V6 host, 53)) :: acc
           end else match String.cut ~sep:"#" line with
           | Some (host, port) ->
               (* IPv4 with non-standard port *)
               let host = Ipaddr.V4.of_string_exn host in
               let port = int_of_string port in
               (`Nameserver (Ipaddr.V4 host, port)) :: acc
           | None ->
               (* IPv4 with standard port *)
               let host = Ipaddr.V4.of_string_exn line in
               (`Nameserver (Ipaddr.V4 host, 53)) :: acc
         end else if String.is_prefix ~affix:zone_prefix line then begin
           let line = String.with_range ~first:(String.length zone_prefix) line in
           (`Zones (String.cuts ~sep:" " line)) :: acc
         end else if String.is_prefix ~affix:search_prefix line then begin
           let line = String.with_range ~first:(String.length search_prefix) line in
           (`Search (String.cuts ~sep:" " line)) :: acc
         end else if String.is_prefix ~affix:timeout_prefix line then begin
           let line = String.with_range ~first:(String.length timeout_prefix) line in
           (`Timeout (int_of_string @@ String.trim ~drop:whitespace line)) :: acc
         end else if String.is_prefix ~affix:order_prefix line then begin
           let line = String.with_range ~first:(String.length order_prefix) line in
           (`Order (int_of_string @@ String.trim ~drop:whitespace line)) :: acc
         end else if String.is_prefix ~affix:assume_offline_after_prefix line then begin
           let line = String.with_range ~first:(String.length assume_offline_after_prefix) line in
           (`Offline (int_of_string @@ String.trim ~drop:whitespace line)) :: acc
         end else acc
      ) []
    (* Merge the zones and nameservers together *)
    |> List.fold_left
      (fun (zones, timeout, order, acc) line -> match zones, timeout, order, line with
        | _, timeout, order, `Zones zones -> zones, timeout, order, acc
        | zones, _, order, `Timeout timeout -> zones, Some timeout, order, acc
        | zones, timeout, _, `Order order -> zones, timeout, order, acc
        | zones, timeout_ms, order, `Nameserver (ip, port) ->
            let zones = List.map (String.cuts ~sep:"." ?rev:None ?empty:None) zones |> Domain.Set.of_list in
            let server = { Server.address = { Address.ip; port }; zones; timeout_ms; order } in
            [], None, 0, { acc with servers = Server.Set.add server acc.servers }
        | _, _, _, `Search search ->
            zones, timeout, order, { acc with search }
        | _, _, _, `Offline n ->
            zones, timeout, order, { acc with assume_offline_after_drops = Some n }
      ) ([], None, 0, { servers = Server.Set.empty; search = []; assume_offline_after_drops = None })
    |> (fun (_, _, _, x) -> Ok x)
  with e -> Error (`Msg (Printf.sprintf "Failed to parse configuration: %s" (Printexc.to_string e)))

let to_string t =
  let nameservers = Server.Set.fold
      (fun server acc ->
         [ nameserver_prefix ^ (Ipaddr.to_string server.Server.address.Address.ip) ^ "#" ^ (string_of_int server.Server.address.Address.port) ]
         @ (if server.Server.zones <> Domain.Set.empty then [ zone_prefix ^ (String.concat " " @@ List.map Domain.to_string @@ Domain.Set.elements server.Server.zones) ] else [])
         @ (match server.Server.timeout_ms with None -> [] | Some t -> [ timeout_prefix ^ (string_of_int t) ])
         @ [ order_prefix ^ (string_of_int server.Server.order) ]
         @ acc
      ) t.servers [] in
  let search = List.map
      (fun search ->
         search_prefix ^ search
      ) t.search in
  String.concat "\n" (nameservers @ search)

module Unix = struct
  let of_resolv_conf txt =
    let open Dns.Resolvconf in
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
    let servers = List.fold_left (fun acc x -> match x with
      | KeywordValue.Nameserver(ip, Some port) ->
          Server.Set.add { Server.address = { Address.ip; port }; zones = Domain.Set.empty; timeout_ms = None; order = 0 } acc
      | KeywordValue.Nameserver(ip, None) ->
          Server.Set.add { Server.address = { Address.ip; port = 53 }; zones = Domain.Set.empty; timeout_ms = None; order = 0 } acc
      | _ -> acc
      ) Server.Set.empty config in
    let search = List.fold_left (fun acc x -> match x with
      | KeywordValue.Search names -> names @ acc
      | _ -> acc
      ) [] config |> List.rev in
    let assume_offline_after_drops = None in
    Ok { servers; search; assume_offline_after_drops }
end

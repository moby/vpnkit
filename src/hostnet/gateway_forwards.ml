let src =
    let src = Logs.Src.create "gateway_forwards" ~doc:"Manages IP forwarding from the gateway IP" in
    Logs.Src.set_level src (Some Logs.Info);
    src

module Log = (val Logs.src_log src : Logs.LOG)

type protocol =
  | Tcp
  | Udp

type forward = {
    protocol: protocol;
    external_port: int;
    internal_ip: Ipaddr.V4.t;
    internal_port: int;
}

let forward_to_json t =
    let open Ezjsonm in
    dict [
        "protocol", string (match t.protocol with Tcp -> "tcp" | Udp -> "udp");
        "external_port", int t.external_port;
        "internal_ip", string (Ipaddr.V4.to_string t.internal_ip);
        "internal_port", int t.internal_port;
    ]

let forward_of_json j =
    let open Ezjsonm in
    let protocol = match get_string @@ find j [ "protocol" ] with
      | "tcp" -> Tcp
      | "udp" -> Udp
      | _ -> raise (Parse_error(j, "protocol should be tcp or udp")) in
    let external_port = get_int @@ find j [ "external_port" ] in
    let internal_port = get_int @@ find j [ "internal_port" ] in
    let internal_ip = match Ipaddr.V4.of_string @@ get_string @@ find j [ "internal_ip" ] with
      | Error (`Msg m) -> raise (Parse_error(j, "internal_ip should be an IPv4 address: " ^ m))
      | Ok x -> x in
    {
        protocol; external_port; internal_ip; internal_port;
    }

type t = forward list

let to_json = Ezjsonm.list forward_to_json
let of_json = Ezjsonm.get_list forward_of_json

let to_string x = Ezjsonm.to_string @@ to_json x
let of_string x =
    try
        Ok (of_json @@ Ezjsonm.from_string x)
    with Ezjsonm.Parse_error(_v, msg) ->
        Error (`Msg msg)

let dynamic = ref []

let static = ref []

let all = ref []

let set_static xs =
    static := xs;
    all := !static @ !dynamic;
    Log.info (fun f -> f "New Gateway forward configuration: %s" (to_string !all))

let update xs =
    dynamic := xs;
    all := !static @ !dynamic;
    Log.info (fun f -> f "New Gateway forward configuration: %s" (to_string !all))

module Udp = struct
  let mem port = List.exists (fun f -> f.protocol = Udp && f.external_port = port) !all
  let find port =
    let f = List.find (fun f -> f.protocol = Udp && f.external_port = port) !all in
    f.internal_ip, f.internal_port
end

module Tcp = struct
  let mem port = List.exists (fun f -> f.protocol = Tcp && f.external_port = port) !all
  let find port =
    let f = List.find (fun f -> f.protocol = Tcp && f.external_port = port) !all in
    f.internal_ip, f.internal_port
end
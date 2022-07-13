let src =
  let src =
    Logs.Src.create "forwards" ~doc:"Forwards TCP/UDP streams to local services"
  in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Protocol = struct
  type t = [ `Tcp ]
  (* consider UDP later *)

  open Ezjsonm

  let to_json t = string (match t with `Tcp -> "tcp")

  let of_json j =
    match get_string j with
    | "tcp" -> `Tcp
    | _ -> raise (Parse_error (j, "protocol should be tcp"))
end

type forward = {
  protocol : Protocol.t;
  dst_prefix : Ipaddr.Prefix.t;
  dst_port : int;
  path : string; (* unix domain socket path *)
}

let forward_to_json t =
  let open Ezjsonm in
  dict
    [
      ("protocol", Protocol.to_json t.protocol);
      ("dst_prefix", string (Ipaddr.Prefix.to_string t.dst_prefix));
      ("dst_port", int t.dst_port);
      ("path", string t.path);
    ]

let forward_of_json j =
  let open Ezjsonm in
  let protocol = Protocol.of_json @@ find j [ "protocol" ] in
  let dst_port = get_int @@ find j [ "dst_port" ] in
  let path = get_string @@ find j [ "path" ] in
  let dst_prefix =
    match Ipaddr.Prefix.of_string @@ get_string @@ find j [ "dst_prefix" ] with
    | Error (`Msg m) ->
        raise (Parse_error (j, "dst_ip should be an IP prefix: " ^ m))
    | Ok x -> x
  in
  { protocol; dst_prefix; dst_port; path }

type t = forward list

let to_json = Ezjsonm.list forward_to_json
let of_json = Ezjsonm.get_list forward_of_json
let to_string x = Ezjsonm.to_string @@ to_json x

let of_string x =
  try Ok (of_json @@ Ezjsonm.from_string x) with
  | Ezjsonm.Parse_error (_v, msg) -> Error (`Msg msg)
  | e -> Error (`Msg (Printf.sprintf "parsing %s: %s" x (Printexc.to_string e)))

let dynamic = ref []
let static = ref []
let all = ref []

let set_static xs =
  static := xs;
  all := !static @ !dynamic;
  Log.info (fun f -> f "New Forward configuration: %s" (to_string !all))

let update xs =
  dynamic := xs;
  all := !static @ !dynamic;
  Log.info (fun f -> f "New Forward configuration: %s" (to_string !all))

module Tcp = struct
  let any_port = 0

  let mem (dst_ip, dst_port) =
    List.exists
      (fun f ->
        f.protocol = `Tcp
        && Ipaddr.Prefix.mem dst_ip f.dst_prefix
        && (f.dst_port = any_port || f.dst_port = dst_port))
      !all

  let find (dst_ip, dst_port) =
    let f =
      List.find
        (fun f ->
          f.protocol = `Tcp
          && Ipaddr.Prefix.mem dst_ip f.dst_prefix
          && (f.dst_port = any_port || f.dst_port = dst_port))
        !all
    in
    f.path
end

let src =
  let src = Logs.Src.create "vmnet_proto" ~doc:"vmnet_proto" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let ethernet_header_length = 14 (* no VLAN *)

module Init = struct
  type t = { magic : string; version : int32; commit : string }

  let to_string t =
    Fmt.str "{ magic = %s; version = %ld; commit = %s }" t.magic t.version
      t.commit

  let sizeof = 5 + 4 + 40

  let default =
    {
      magic = "VMN3T";
      version = 22l;
      commit = "0123456789012345678901234567890123456789";
    }

  let marshal t rest =
    Cstruct.blit_from_string t.magic 0 rest 0 5;
    Cstruct.LE.set_uint32 rest 5 t.version;
    Cstruct.blit_from_string t.commit 0 rest 9 40;
    Cstruct.shift rest sizeof

  let unmarshal rest =
    let magic = Cstruct.(to_string @@ sub rest 0 5) in
    let version = Cstruct.LE.get_uint32 rest 5 in
    let commit = Cstruct.(to_string @@ sub rest 9 40) in
    let rest = Cstruct.shift rest sizeof in
    ({ magic; version; commit }, rest)
end

module Command = struct
  type t =
    | Ethernet of Uuidm.t (* 36 bytes *)
    | Preferred_ipv4 of Uuidm.t (* 36 bytes *) * Ipaddr.V4.t
    | Bind_ipv4 of Ipaddr.V4.t * int * bool

  let to_string = function
    | Ethernet x -> Fmt.str "Ethernet %a" Uuidm.pp x
    | Preferred_ipv4 (uuid, ip) ->
        Fmt.str "Preferred_ipv4 %a %a" Uuidm.pp uuid Ipaddr.V4.pp ip
    | Bind_ipv4 (ip, port, tcp) ->
        Fmt.str "Bind_ipv4 %a %d %b" Ipaddr.V4.pp ip port tcp

  let sizeof = 1 + 36 + 4

  let marshal t rest =
    match t with
    | Ethernet uuid ->
        Cstruct.set_uint8 rest 0 1;
        let rest = Cstruct.shift rest 1 in
        let uuid_str = Uuidm.to_string uuid in
        Cstruct.blit_from_string uuid_str 0 rest 0 (String.length uuid_str);
        Cstruct.shift rest (String.length uuid_str)
    | Preferred_ipv4 (uuid, ip) ->
        Cstruct.set_uint8 rest 0 8;
        let rest = Cstruct.shift rest 1 in
        let uuid_str = Uuidm.to_string uuid in
        Cstruct.blit_from_string uuid_str 0 rest 0 (String.length uuid_str);
        let rest = Cstruct.shift rest (String.length uuid_str) in
        Cstruct.LE.set_uint32 rest 0 (Ipaddr.V4.to_int32 ip);
        Cstruct.shift rest 4
    | Bind_ipv4 (ip, port, stream) ->
        Cstruct.set_uint8 rest 0 6;
        let rest = Cstruct.shift rest 1 in
        Cstruct.LE.set_uint32 rest 0 (Ipaddr.V4.to_int32 ip);
        let rest = Cstruct.shift rest 4 in
        Cstruct.LE.set_uint16 rest 0 port;
        let rest = Cstruct.shift rest 2 in
        Cstruct.set_uint8 rest 0 (if stream then 0 else 1);
        Cstruct.shift rest 1

  let unmarshal rest =
    let process_uuid uuid_str =
      if String.compare (String.make 36 '\000') uuid_str = 0 then (
        let random_uuid = Uuidm.v `V4 in
        Log.info (fun f ->
            f "Generated UUID on behalf of client: %a" Uuidm.pp random_uuid);
        (* generate random uuid on behalf of client if client sent
           array of \0 *)
        Some random_uuid)
      else Uuidm.of_string uuid_str
    in
    match Cstruct.get_uint8 rest 0 with
    | 1 -> (
        (* ethernet *)
        let uuid_str = Cstruct.(to_string (sub rest 1 36)) in
        let rest = Cstruct.shift rest 37 in
        match process_uuid uuid_str with
        | Some uuid -> Ok (Ethernet uuid, rest)
        | None -> Error (`Msg (Printf.sprintf "Invalid UUID: %s" uuid_str)))
    | 8 -> (
        (* preferred_ipv4 *)
        let uuid_str = Cstruct.(to_string (sub rest 1 36)) in
        let rest = Cstruct.shift rest 37 in
        let ip = Ipaddr.V4.of_int32 (Cstruct.LE.get_uint32 rest 0) in
        let rest = Cstruct.shift rest 4 in
        match process_uuid uuid_str with
        | Some uuid -> Ok (Preferred_ipv4 (uuid, ip), rest)
        | None -> Error (`Msg (Printf.sprintf "Invalid UUID: %s" uuid_str)))
    | n -> Error (`Msg (Printf.sprintf "Unknown command: %d" n))
end

module Vif = struct
  type t = { mtu : int; max_packet_size : int; client_macaddr : Macaddr.t }

  let to_string t =
    Fmt.str "{ mtu = %d; max_packet_size = %d; client_macaddr = %s }" t.mtu
      t.max_packet_size
      (Macaddr.to_string t.client_macaddr)

  let create client_macaddr mtu () =
    let max_packet_size = mtu + 50 in
    { mtu; max_packet_size; client_macaddr }

  let sizeof = 2 + 2 + 6

  let marshal t rest =
    Cstruct.LE.set_uint16 rest 0 t.mtu;
    Cstruct.LE.set_uint16 rest 2 t.max_packet_size;
    Cstruct.blit_from_string (Macaddr.to_octets t.client_macaddr) 0 rest 4 6;
    Cstruct.shift rest sizeof

  let unmarshal rest =
    let mtu = Cstruct.LE.get_uint16 rest 0 in
    let max_packet_size = Cstruct.LE.get_uint16 rest 2 in
    let mac = Cstruct.(to_string @@ sub rest 4 6) in
    try
      let client_macaddr = Macaddr.of_octets_exn mac in
      Ok ({ mtu; max_packet_size; client_macaddr }, Cstruct.shift rest sizeof)
    with _ -> Error (`Msg (Printf.sprintf "Failed to parse MAC: [%s]" mac))
end

module Response = struct
  type t =
    | Vif of Vif.t
    (* 10 bytes *)
    | Disconnect of string
  (* disconnect reason *)

  let sizeof = 1 + 1 + 256 (* leave room for error message and length *)

  let marshal t rest =
    match t with
    | Vif vif ->
        Cstruct.set_uint8 rest 0 1;
        let rest = Cstruct.shift rest 1 in
        Vif.marshal vif rest
    | Disconnect reason ->
        Cstruct.set_uint8 rest 0 2;
        let rest = Cstruct.shift rest 1 in
        Cstruct.set_uint8 rest 0 (String.length reason);
        let rest = Cstruct.shift rest 1 in
        Cstruct.blit_from_string reason 0 rest 0 (String.length reason);
        Cstruct.shift rest (String.length reason)

  let unmarshal rest =
    match Cstruct.get_uint8 rest 0 with
    | 1 -> (
        (* vif *)
        let rest = Cstruct.shift rest 1 in
        let vif = Vif.unmarshal rest in
        match vif with
        | Ok (vif, rest) -> Ok (Vif vif, rest)
        | Error msg -> Error msg)
    | 2 ->
        (* disconnect *)
        let rest = Cstruct.shift rest 1 in
        let str_len = Cstruct.get_uint8 rest 0 in
        let rest = Cstruct.shift rest 1 in
        let reason_str = Cstruct.(to_string (sub rest 0 str_len)) in
        let rest = Cstruct.shift rest str_len in
        Ok (Disconnect reason_str, rest)
    | n -> Error (`Msg (Printf.sprintf "Unknown response: %d" n))
end

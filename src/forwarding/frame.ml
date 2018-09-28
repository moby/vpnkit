
module Destination = struct
  type t = {
    proto: [ `Tcp | `Udp ];
    ip: Ipaddr.t;
    port: int;
  }

  let sizeof t =
    1 + 2 + (match t.ip with Ipaddr.V4 _ -> 4 | Ipaddr.V6 _ -> 16) + 2

  let write t buf =
    (* Matches the Go definition *)
    let proto = match t.proto with
      | `Tcp -> 1
      | `Udp -> 2 in
    let ip = match t.ip with
      | Ipaddr.V4 ip -> Ipaddr.V4.to_bytes ip
      | Ipaddr.V6 ip -> Ipaddr.V6.to_bytes ip in
    let header = Cstruct.sub buf 0 (sizeof t) in
    Cstruct.set_uint8 header 0 proto;
    Cstruct.LE.set_uint16 header 1 (String.length ip);
    Cstruct.blit_from_string ip 0 header 3 (String.length ip);
    Cstruct.LE.set_uint16 header (3 + (String.length ip)) t.port;
    header

  let read buf =
    let proto = match Cstruct.get_uint8 buf 0 with
      | 1 -> `Tcp
      | 2 -> `Udp
      | x -> failwith (Printf.sprintf "Unknown Destination protocol: %d" x) in
    let ip_len = Cstruct.LE.get_uint16 buf 1 in
    let bytes = Cstruct.(to_string (sub buf 3 ip_len)) in
    let ip = match ip_len with
      | 4 -> Ipaddr.V4 (Ipaddr.V4.of_bytes_exn @@ bytes)
      | 16 -> Ipaddr.V6 (Ipaddr.V6.of_bytes_exn @@ bytes)
      | _ -> failwith (Printf.sprintf "Failed to parse IP address of length %d: %s" ip_len (String.escaped bytes)) in
    let port = Cstruct.LE.get_uint16 buf (3 + (String.length bytes)) in
    { proto; ip; port }

end

module Udp = struct
  type t = {
    ip: Ipaddr.t;
    port: int;
    payload_length: int;
  }
  let write_header t buf =
    (* Leave space for a uint16 frame length *)
    let rest = Cstruct.shift buf 2 in
    (* uint16 IP address length *)
    let ip_bytes =
      match t.ip with
      | Ipaddr.V4 ipv4 -> Ipaddr.V4.to_bytes ipv4
      | Ipaddr.V6 ipv6 -> Ipaddr.V6.to_bytes ipv6
    in
    let ip_bytes_len = String.length ip_bytes in
    Cstruct.LE.set_uint16 rest 0 ip_bytes_len;
    let rest = Cstruct.shift rest 2 in
    (* IP address bytes *)
    Cstruct.blit_from_string ip_bytes 0 rest 0 ip_bytes_len;
    let rest = Cstruct.shift rest ip_bytes_len in
    (* uint16 Port *)
    Cstruct.LE.set_uint16 rest 0 t.port;
    let rest = Cstruct.shift rest 2 in
    (* uint16 Zone length *)
    Cstruct.LE.set_uint16 rest 0 0;
    let rest = Cstruct.shift rest 2 in
    (* Zone string *)
    (* uint16 payload length *)
    Cstruct.LE.set_uint16 rest 0 t.payload_length;
    let rest = Cstruct.shift rest 2 in
    let header_len = rest.Cstruct.off - buf.Cstruct.off in
    let frame_len = header_len + t.payload_length in
    let header = Cstruct.sub buf 0 header_len in
    (* Add an overall frame length at the start *)
    Cstruct.LE.set_uint16 header 0 frame_len;
    header

  let read buf =
    (* uint16 frame length *)
    let rest = Cstruct.shift buf 2 in
    (* uint16 IP address length *)
    let ip_bytes_len = Cstruct.LE.get_uint16 rest 0 in
    (* IP address bytes *)
    let ip_bytes_string = Cstruct.(to_string (sub rest 2 ip_bytes_len)) in
    let rest = Cstruct.shift rest (2 + ip_bytes_len) in
    let ip =
      let open Ipaddr in
      if String.length ip_bytes_string = 4
      then V4 (V4.of_bytes_exn ip_bytes_string)
      else V6 (Ipaddr.V6.of_bytes_exn ip_bytes_string)
    in
    (* uint16 Port *)
    let port = Cstruct.LE.get_uint16 rest 0 in
    let rest = Cstruct.shift rest 2 in
    (* uint16 Zone length *)
    let zone_length = Cstruct.LE.get_uint16 rest 0 in
    let rest = Cstruct.shift rest (2 + zone_length) in
    (* uint16 payload length *)
    let payload_length = Cstruct.LE.get_uint16 rest 0 in
    (* payload *)
    let payload = Cstruct.sub rest 2 payload_length in
    { ip; port; payload_length }, payload
end

type connection =
  | Dedicated
  | Multiplexed

type command =
  | Open of connection * Destination.t
  | Close
  | Shutdown
  | Data of int32
  | Window of int64

type t = {
  command: command;
  id: int32;
}

let sizeof t = match t.command with
  | Open (_, d) -> 1 + 1 + 4 + 1 + (Destination.sizeof d)
  | Close
  | Shutdown -> 1 + 1 + 4
  | Data _ -> 1 + 1 + 4 + 4
  | Window _ -> 1 + 1 + 4 + 8

let write t buf =
  Cstruct.LE.set_uint32 buf 1 t.id;
  begin match t.command with
  | Open (connection, destination) ->
    Cstruct.set_uint8 buf 0 1;
    Cstruct.set_uint8 buf 5 (match connection with Dedicated -> 1 | Multiplexed -> 2);
    let (_: Cstruct.t) = Destination.write destination (Cstruct.shift buf 6) in
    ()
  | Close->
    Cstruct.set_uint8 buf 0 2
  | Shutdown->
    Cstruct.set_uint8 buf 0 3
  | Data payloadlen ->
    Cstruct.set_uint8 buf 0 4;
    Cstruct.LE.set_uint32 buf 5 payloadlen
  | Window seq ->
    Cstruct.set_uint8 buf 0 5;
    Cstruct.LE.set_uint64 buf 5 seq
  end;
  Cstruct.sub buf 0 (sizeof t)

let read buf =
  let id = Cstruct.LE.get_uint32 buf 1 in
  match Cstruct.get_uint8 buf 0 with
  | 1 ->
    let connection = match Cstruct.get_uint8 buf 5 with
    | 1 -> Dedicated
    | 2 -> Multiplexed
    | x -> failwith (Printf.sprintf "Unknown connection type: %d" x) in
    let destination = Destination.read (Cstruct.shift buf 6) in
    { command = Open(connection, destination); id }
  | 2 ->
    { command = Close; id }
  | 3 ->
    { command = Shutdown; id }
  | 4 ->
    let payloadlen = Cstruct.LE.get_uint32 buf 5 in
    { command = Data payloadlen; id }
  | 5 ->
    let seq = Cstruct.LE.get_uint64 buf 5 in
    { command = Window seq; id }
  | x -> failwith (Printf.sprintf "Unknown command type: %d" x)

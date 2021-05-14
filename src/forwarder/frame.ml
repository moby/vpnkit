
module Destination = struct
  type port = int
  type path = string
  type t = [
    | `Tcp of Ipaddr.t * port
    | `Udp of Ipaddr.t * port
    | `Unix of path
  ]

  let to_string = function
    | `Tcp (ip, port) ->
      Printf.sprintf "TCP %s:%d" (Ipaddr.to_string ip) port
    | `Udp (ip, port) ->
      Printf.sprintf "UDP %s:%d" (Ipaddr.to_string ip) port
    | `Unix path ->
      Printf.sprintf "Unix %s" path

  let sizeof = function
    | `Tcp (ip, _)
    | `Udp (ip, _) ->
      1 + 2 + (match ip with Ipaddr.V4 _ -> 4 | Ipaddr.V6 _ -> 16) + 2
    | `Unix path ->
      1 + 2 + (String.length path)

  let write t rest =
    (* Matches the Go definition *)
    let proto = match t with
      | `Tcp (_, _) -> 1
      | `Udp (_, _) -> 2
      | `Unix _ -> 3 in
    let header = Cstruct.sub rest 0 (sizeof t) in
    Cstruct.set_uint8 rest 0 proto;
    let rest = Cstruct.shift header 1 in

    let write_string s buf =
      Cstruct.LE.set_uint16 buf 0 (String.length s);
      Cstruct.blit_from_string s 0 buf 2 (String.length s);
      Cstruct.shift buf (2 + (String.length s)) in

    let write_ip ip buf =
      let ip = match ip with
        | Ipaddr.V4 ip -> Ipaddr.V4.to_octets ip
        | Ipaddr.V6 ip -> Ipaddr.V6.to_octets ip in
      write_string ip buf in

    match t with
    | `Tcp(ip, port)
    | `Udp(ip, port) ->
      let rest = write_ip ip rest in
      Cstruct.LE.set_uint16 rest 0 port;
      header
    | `Unix path ->
      let _rest = write_string path rest in
      header

  let read buf =
    let read_string (rest: Cstruct.t) =
      let str_len : int = Cstruct.LE.get_uint16 rest 0 in
      let str = Cstruct.(to_string (sub rest 2 str_len)) in
      str, Cstruct.shift rest (2 + str_len) in
    let read_ip rest =
      let str, rest = read_string rest in
      match String.length str with
      | 4 -> Ipaddr.V4 (Ipaddr.V4.of_octets_exn @@ str), rest
      | 16 -> Ipaddr.V6 (Ipaddr.V6.of_octets_exn @@ str), rest
      | _ -> failwith (Printf.sprintf "Failed to parse IP address of length %d: %s" (String.length str) (String.escaped str)) in

    let rest = Cstruct.shift buf 1 in
    match Cstruct.get_uint8 buf 0 with
    | 1 ->
      let ip, rest = read_ip rest in
      let port = Cstruct.LE.get_uint16 rest 0 in
      `Tcp (ip, port)
    | 2 ->
      let ip, rest = read_ip rest in
      let port = Cstruct.LE.get_uint16 rest 0 in
      `Udp (ip, port)
    | 3 ->
      let path, _ = read_string rest in
      `Unix path
    | x ->
      failwith (Printf.sprintf "Unknown Destination protocol: %d" x)

end

module Udp = struct
  type t = {
    ip: Ipaddr.t;
    port: int;
    payload_length: int;
  }
  let max_sizeof =
    2 + (* length of frame *)
    2 + (* length of IP *)
    16 + (* IPv6 *)
    2 + (* port *)
    2 + (* length of Zone, which is "" *)
    2 (* length of payload length *)
  let write_header t buf =
    (* Leave space for a uint16 frame length *)
    let rest = Cstruct.shift buf 2 in
    (* uint16 IP address length *)
    let ip_bytes =
      match t.ip with
      | Ipaddr.V4 ipv4 -> Ipaddr.V4.to_octets ipv4
      | Ipaddr.V6 ipv6 -> Ipaddr.V6.to_octets ipv6
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
      then V4 (V4.of_octets_exn ip_bytes_string)
      else V6 (Ipaddr.V6.of_octets_exn ip_bytes_string)
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

let string_of_connection = function
  | Dedicated -> "Dedicated"
  | Multiplexed -> "Multiplexed"

type command =
  | Open of connection * Destination.t
  | Close
  | Shutdown
  | Data of int32
  | Window of int64

let string_of_command = function
  | Open(connection, destination) -> Printf.sprintf "Open(%s, %s)" (string_of_connection connection) (Destination.to_string destination)
  | Close -> "Close"
  | Shutdown -> "Shutdown"
  | Data len -> Printf.sprintf "Data length = %ld" len
  | Window seq -> Printf.sprintf "Window seq = %Ld" seq

type t = {
  command: command;
  id: int32;
}

let to_string { command; id } =
  Printf.sprintf "Frame { command = %s; id = %ld }" (string_of_command command) id

let sizeof t = match t.command with
  | Open (_, d) -> 2 + 1 + 4 + 1 + (Destination.sizeof d)
  | Close
  | Shutdown -> 2 + 1 + 4
  | Data _ -> 2 + 1 + 4 + 4
  | Window _ -> 2 + 1 + 4 + 8

let write t buf =
  Cstruct.LE.set_uint16 buf 0 (sizeof t);
  Cstruct.LE.set_uint32 buf 3 t.id;
  begin match t.command with
  | Open (connection, destination) ->
    Cstruct.set_uint8 buf 2 1;
    Cstruct.set_uint8 buf 7 (match connection with Dedicated -> 1 | Multiplexed -> 2);
    let (_: Cstruct.t) = Destination.write destination (Cstruct.shift buf 8) in
    ()
  | Close->
    Cstruct.set_uint8 buf 2 2
  | Shutdown->
    Cstruct.set_uint8 buf 2 3
  | Data payloadlen ->
    Cstruct.set_uint8 buf 2 4;
    Cstruct.LE.set_uint32 buf 7 payloadlen
  | Window seq ->
    Cstruct.set_uint8 buf 2 5;
    Cstruct.LE.set_uint64 buf 7 seq
  end;
  Cstruct.sub buf 0 (sizeof t)

let read buf =
  (* skip the length *)
  let id = Cstruct.LE.get_uint32 buf 3 in
  match Cstruct.get_uint8 buf 2 with
  | 1 ->
    let connection = match Cstruct.get_uint8 buf 7 with
    | 1 -> Dedicated
    | 2 -> Multiplexed
    | x -> failwith (Printf.sprintf "Unknown connection type: %d" x) in
    let destination = Destination.read (Cstruct.shift buf 8) in
    { command = Open(connection, destination); id }
  | 2 ->
    { command = Close; id }
  | 3 ->
    { command = Shutdown; id }
  | 4 ->
    let payloadlen = Cstruct.LE.get_uint32 buf 7 in
    { command = Data payloadlen; id }
  | 5 ->
    let seq = Cstruct.LE.get_uint64 buf 7 in
    { command = Window seq; id }
  | x -> failwith (Printf.sprintf "Unknown command type: %d" x)

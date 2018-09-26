
module Connect = struct

  type t = {
    proto: [ `Tcp | `Udp ];
    ip: Ipaddr.t;
    port: int;
  }

  let sizeof = 1 + 2 + 4 + 2

  let write t buf =
    (* Matches the Go definition *)
    let proto = match t.proto with
      | `Tcp -> 1
      | `Udp -> 2 in
    let ip = match t.ip with
      | Ipaddr.V4 ip -> Ipaddr.V4.to_bytes ip
      | Ipaddr.V6 ip -> Ipaddr.V6.to_bytes ip in
    let header = Cstruct.sub buf 0 sizeof in
    Cstruct.set_uint8 header 0 proto;
    Cstruct.LE.set_uint16 header 1 4;
    Cstruct.blit_from_string ip 0 header 3 4;
    Cstruct.LE.set_uint16 header 7 t.port;
    header

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
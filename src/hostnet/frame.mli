type icmp =
  | Echo:     { seq: int; id: int; payload: Cstruct.t } -> icmp
  | Time_exceeded: { ipv4: (ipv4, [ `Msg of string ]) result } -> icmp
  | Destination_unreachable: { ipv4: (ipv4, [ `Msg of string ]) result } -> icmp
  | Unknown_icmp: { ty: int } -> icmp

and ipv4 = {
  src: Ipaddr.V4.t; dst: Ipaddr.V4.t;
  dnf: bool; ihl: int;
  ttl: int; raw: Cstruct.t; payload: t
}

and t =
  | Ethernet: { src: Macaddr.t; dst: Macaddr.t; payload: t } -> t
  | Arp:      { op: [ `Request | `Reply | `Unknown ] } -> t
  | Icmp:     { ty: int; code: int; raw: Cstruct.t; icmp: icmp } -> t
  | Ipv4:     ipv4 -> t
  | Udp:      { src: int; dst: int; len: int; raw: Cstruct.t; payload: t } -> t
  | Tcp:      { src: int; dst: int; syn: bool; rst: bool; raw: Cstruct.t; payload: t } -> t
  | Payload:  Cstruct.t -> t
  | Unknown:  t

val ipv4: Cstructs.t -> (ipv4, [ `Msg of string ]) result
(** [ipv4 buffers] parses the IPv4 frame in [buffers] *)

val parse: Cstructs.t -> (t, [ `Msg of string]) result
(** [parse buffers] parses the frame in [buffers] *)

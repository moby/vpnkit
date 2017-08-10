type t =
  | Ethernet: { src: Macaddr.t; dst: Macaddr.t; payload: t } -> t
  | Arp:      { op: [ `Request | `Reply | `Unknown ] } -> t
  | Icmp:     { ty: int; code: int; seq: int; id: int;
                raw: Cstruct.t; payload: t } -> t
  | Ipv4:     { src: Ipaddr.V4.t; dst: Ipaddr.V4.t; dnf: bool; ihl: int;
                raw: Cstruct.t; payload: t } -> t
  | Udp:      { src: int; dst: int; len: int; payload: t } -> t
  | Tcp:      { src: int; dst: int; syn: bool; raw: Cstruct.t; payload: t } -> t
  | Payload:  Cstruct.t -> t
  | Unknown:  t

val parse: Cstructs.t -> (t, [ `Msg of string]) result
(** [parse buffers] parses the frame in [buffers] *)

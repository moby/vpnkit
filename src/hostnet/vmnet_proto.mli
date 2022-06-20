val ethernet_header_length : int

module Init : sig
  type t = { magic : string; version : int32; commit : string }

  val to_string : t -> string
  val sizeof : int
  val default : t
  val marshal : t -> Cstruct.t -> Cstruct.t
  val unmarshal : Cstruct.t -> t * Cstruct.t
end

module Command : sig
  type t =
    | Ethernet of Uuidm.t (* 36 bytes *)
    | Preferred_ipv4 of Uuidm.t (* 36 bytes *) * Ipaddr.V4.t
    | Bind_ipv4 of Ipaddr.V4.t * int * bool

  val to_string : t -> string
  val sizeof : int
  val marshal : t -> Cstruct.t -> Cstruct.t
  val unmarshal : Cstruct.t -> (t * Cstruct.t, [ `Msg of string ]) result
end

module Vif : sig
  type t = { mtu : int; max_packet_size : int; client_macaddr : Macaddr.t }

  val create : Macaddr.t -> int -> unit -> t
  val to_string : t -> string
  val sizeof : int
  val marshal : t -> Cstruct.t -> Cstruct.t
  val unmarshal : Cstruct.t -> (t * Cstruct.t, [> `Msg of string ]) result
end

module Response : sig
  type t =
    | Vif of Vif.t
    (* 10 bytes *)
    | Disconnect of string
  (* disconnect reason *)

  val sizeof : int
  val marshal : t -> Cstruct.t -> Cstruct.t
  val unmarshal : Cstruct.t -> (t * Cstruct.t, [> `Msg of string ]) result
end

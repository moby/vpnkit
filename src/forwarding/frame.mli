
module Destination : sig
  type t = {
    proto: [ `Tcp | `Udp ];
    ip: Ipaddr.t;
    port: int;
  }

  val sizeof: t -> int

  val write: t -> Cstruct.t -> Cstruct.t
  (** [write t buf] writes t into [buf] and returns the part of [buf] containing [t] *)
  
  val read: Cstruct.t -> t
  (** [read buf] reads [t] from [buf] or raises an exception *)

end

module Udp : sig
  type t = {
    ip: Ipaddr.t;
    port: int;
    payload_length: int;
  }

  val write_header: t -> Cstruct.t -> Cstruct.t
  (** [write t buf] writes t into [buf] and returns the part of [buf] containing [t] *)

  val read: Cstruct.t -> t * Cstruct.t
    (** [read buf] reads [t] from [buf] and returns [t, payload] or raises an exception *)
end

type connection =
  | Dedicated   (** the connection will be dedicated to this channel *)
  | Multiplexed (** multiple channels will be multiplexed within this connection *)
(** Describes the relationship between the connection and the connections within *)

type command =
  | Open of connection * Destination.t (** open a channel to a destination *)
  | Close                              (** request / confirm close a channel *)
  | Shutdown                           (** flush and shutdown this side of a channel *)
  | Data of int32                      (** payload on a given channel *)
  | Window of int64                    (** sequence number to allow up to *)
(** Frames containing commands open, close and transmit data along connections *)

type t = {
  command: command;
  id: int32;        (** The channel id which this frame refers to *)
}
(** A framed message sent from one side to the other *)

val sizeof: t -> int

val write: t -> Cstruct.t -> Cstruct.t
(** [write t buf] writes t into [buf] and returns the part of [buf] containing [t] *)

val read: Cstruct.t -> t
(** [read buf] reads [t] from [buf] or raises an exception *)

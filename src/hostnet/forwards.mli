module Protocol : sig
  type t = [ `Tcp ]
  (* consider UDP later *)
end

type forward = {
  protocol : Protocol.t;
  dst_prefix : Ipaddr.Prefix.t;
  dst_port : int;
  path : string; (* unix domain socket path *)
}

type t = forward list

val to_string : t -> string
val of_string : string -> (t, [ `Msg of string ]) result

val set_static : t -> unit
(** update the static forwarding table *)

val update : t -> unit
(** update the dynamic forwarding table *)

module Tcp : sig
  val mem : Ipaddr.t * int -> bool
  (** [mem dst_ip dst_port] is true if there is a rule to forward TCP to [dst_ip,dst_port]. *)

  val find : Ipaddr.t * int -> string
  (** [find dst_ip dst_port] returns the internal path to forward the TCP connection to. *)
end

module Stream : sig
  module Tcp : Sig.FLOW_CLIENT with type address = Ipaddr.t * int
end

module Test (Clock : Mirage_clock.MCLOCK) : sig
  type server

  val start_forwarder : string -> server Lwt.t
  val shutdown : server -> unit Lwt.t
end

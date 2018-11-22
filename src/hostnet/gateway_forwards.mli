type protocol =
  | Tcp
  | Udp

type forward = {
    protocol: protocol;
    external_port: int;
    internal_ip: Ipaddr.V4.t;
    internal_port: int;
}

type t = forward list

val to_string: t -> string
val of_string: string -> (t, [`Msg of string]) result

val set_static: t -> unit
(** update the static forwarding table *)

val update: t -> unit
(** update the dynamic forwarding table *)

module Udp: sig
  val mem: int -> bool
  (** [mem port] is true if there is a rule to forward UDP from external port [port] *)

  val find: int -> (Ipaddr.V4.t * int)
  (** [find port] returns the internal IP and port to forward UDP on external port [port] *)
end

module Tcp: sig
  val mem: int -> bool
  (** [mem port] is true if there is a rule to forward TCP from external port [port] *)

  val find: int -> (Ipaddr.V4.t * int)
  (** [find port] returns the internal IP and port to forward TCP on external port [port] *)
end
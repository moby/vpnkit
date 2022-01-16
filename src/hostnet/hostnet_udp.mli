(** A simple UDP NAT implementation.

    UDP packets are input and forwarded via datagram sockets. Replies are
    sent back by a callback set by the caller *)

type address = Ipaddr.t * int

type datagram = {
  src: address; (** origin of the packet from the guest *)
  dst: address; (** expected destination of the packet from the guest *)
  intercept: address; (** address we will really send the packet to, pretending to be `dst` *)
  payload: Cstruct.t;
}
(** A UDP datagram *)

type reply = Cstruct.t -> unit Lwt.t

module Make
    (Sockets: Sig.SOCKETS)
    (Clock: Mirage_clock.MCLOCK)
    (Time: Mirage_time.S):
sig

  type t
  (** A UDP NAT implementation *)

  val create: ?max_idle_time:int64 -> ?preserve_remote_port:bool -> ?max_active_flows:int -> unit -> t
  (** Create a UDP NAT implementation which will keep "NAT rules" alive until
      they become idle for the given [?max_idle_time] or until the number of
      flows hits [?max_active_flows] at which point the oldest will be expired.
      If [~preserve_remote_port] is set then reply traffic will come from the
      remote source port, otherwise it will come from the NAT port. *)

  val set_send_reply: t:t -> send_reply:(datagram -> unit Lwt.t) -> unit
  (** Register a reply callback which will be used to send datagrams to the
      NAT client. *)

  val input: t:t -> datagram:datagram -> ttl:int -> unit -> unit Lwt.t
  (** Process an incoming datagram, forwarding it over the Sockets implementation
      and set up a listening rule to catch replies. *)

  module Debug : sig
    type address = Ipaddr.t * int

    type flow = {
        inside: address;
        outside: address;
        last_use_time_ns: int64;
    }

    val get_table: t -> flow list
    (** Return an instantaneous snapshot of the NAT table *)

    val get_max_active_flows: t -> int
  end
end

val external_to_internal: (int, address) Hashtbl.t
(** A mapping of external (host) port to internal address *)
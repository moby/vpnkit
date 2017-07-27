(** A simple UDP NAT implementation.

    UDP packets are input and forwarded via datagram sockets. Replies are
    sent back by a callback set by the caller *)

type address = Ipaddr.t * int

type datagram = {
  src: address;
  dst: address;
  payload: Cstruct.t;
}
(** A UDP datagram *)

type reply = Cstruct.t -> unit Lwt.t

module Make
    (Sockets: Sig.SOCKETS)
    (Clock: Mirage_clock_lwt.MCLOCK)
    (Time: Mirage_time_lwt.S):
sig

  type t
  (** A UDP NAT implementation *)

  val create: ?max_idle_time:int64 -> Clock.t -> t
  (** Create a UDP NAT implementation which will keep "NAT rules" alive until
      they become idle for the given [?max_idle_time] *)

  val set_send_reply: t:t -> send_reply:(datagram -> unit Lwt.t) -> unit
  (** Register a reply callback which will be used to send datagrams to the
      NAT client. *)

  val input: t:t -> datagram:datagram -> unit -> unit Lwt.t
  (** Process an incoming datagram, forwarding it over the Sockets implementation
      and set up a listening rule to catch replies. *)

  val get_nat_table_size: t -> int
  (** Return the current number of allocated NAT table entries *)
end

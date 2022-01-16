(** A simple ICMP NAT implementation.

*)

type address = Ipaddr.V4.t

type datagram = {
  src: address;
  dst: address;
  ty: int;
  code: int;
  seq: int;
  id: int;
  payload: Cstruct.t;
}
(** An ICMP datagram *)

type reply = Cstruct.t -> unit Lwt.t

module Make
    (Sockets: Sig.SOCKETS)
    (Clock: Mirage_clock.MCLOCK)
    (Time: Mirage_time.S)
: sig

  type t
  (** An ICMP NAT implementation *)

  val create: ?max_idle_time:int64 -> unit -> t
  (** Create an ICMP NAT implementation which will keep "NAT rules" alive until
      they become idle for the given [?max_idle_time] *)

  val set_send_reply: t:t -> send_reply:(src:address -> dst:address -> payload:Cstruct.t -> unit Lwt.t) -> unit
  (** Register a reply callback which will be used to send datagrams to the
      NAT client. *)

  val input: t:t -> datagram:datagram -> ttl:int -> unit -> unit Lwt.t
  (** Process an incoming datagram, forwarding it over the Sockets implementation
      and set up a listening rule to catch replies. *)

end

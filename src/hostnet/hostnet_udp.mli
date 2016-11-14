
(** A simple UDP NAT implementation.

    UDP packets are input and forwarded via datagram sockets. Replies are
    sent back by a callback set by the caller *)

type reply = Cstruct.t -> unit Lwt.t

type address = Ipaddr.t * int

module Make(Sockets: Sig.SOCKETS)(Time: V1_LWT.TIME): sig

  type t
  (** A UDP NAT implementation *)

  val create: ?max_idle_time:float -> unit -> t
  (** Create a UDP NAT implementation which will keep "NAT rules" alive until
      they become idle for the given [?max_idle_time] *)

  val input: t:t -> ?userdesc:string -> reply:reply -> src:address -> dst:address -> payload:Cstruct.t -> unit -> unit Lwt.t

  val get_nat_table_size: t -> int
  (** Return the current number of allocated NAT table entries *)
end

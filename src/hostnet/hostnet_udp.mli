
type reply = Cstruct.t -> unit Lwt.t

type address = Ipaddr.t * int

module Make(Sockets: Sig.SOCKETS)(Time: V1_LWT.TIME): sig

  val start_background_gc: unit -> unit

  val input: ?userdesc:string -> oneshot:bool -> reply:reply -> src:address -> dst:address -> payload:Cstruct.t -> unit -> unit Lwt.t

  val get_nat_table_size: unit -> int
  (** Return the current number of allocated NAT table entries *)
end


module Port : sig

  type t

  val of_string: string -> (t, [ `Msg of string ]) result
end

module Make
    (Clock: Mirage_clock_lwt.MCLOCK)
    (Connector: Sig.Connector)
    (Socket: Sig.SOCKETS):
  Active_list.Instance with type clock = Clock.t

val set_allowed_addresses: Ipaddr.t list option -> unit

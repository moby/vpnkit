
module Port : sig
  type t = [
    | `Tcp of Ipaddr.t * int
    | `Udp of Ipaddr.t * int
  ]

  val of_string: string -> (t, [ `Msg of string ]) result
end

module Make
    (Clock: Mirage_clock_lwt.MCLOCK)
    (Connector: Sig.Connector)
    (Socket: Sig.SOCKETS):
  Active_list.Instance with type context = string and type clock = Clock.t

val set_allowed_addresses: Ipaddr.t list option -> unit

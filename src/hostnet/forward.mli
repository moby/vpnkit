
module Port : sig

  type t

  val of_string: string -> (t, [ `Msg of string ]) result
end

module Make
    (Connector: Sig.Connector)
    (Socket: Sig.SOCKETS):
  Active_list.Instance

val set_allowed_addresses: Ipaddr.t list option -> unit

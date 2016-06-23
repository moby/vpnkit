
module Port : sig
  type t = [
    | `Tcp of Ipaddr.V4.t * int
    | `Udp of Ipaddr.t * int
  ]

  val of_string: string -> (t, [ `Msg of string ]) Result.result
end

module Make(Connector: Sig.Connector)(Sockets: Sig.SOCKETS) : sig
  include Active_list.Instance
    with type context = string

end

val set_allowed_addresses: Ipaddr.t list option -> unit

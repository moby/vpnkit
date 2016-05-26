
module Port : sig
  type t = [
    | `Tcp of Ipaddr.V4.t * int
    | `Udp of Ipaddr.V4.t * int
  ]

  val of_string: string -> (t, [ `Msg of string ]) Result.result
end

module Make(Connector: Sig.Connector with type port = Port.t)(Binder: Sig.Binder) : sig
  include Active_list.Instance
    with type context = string

end

val set_allowed_addresses: Ipaddr.t list option -> unit

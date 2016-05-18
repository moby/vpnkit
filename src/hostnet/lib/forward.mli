

module Make(Connector: Sig.Connector)(Binder: Sig.Binder) : sig
  include Active_list.Instance
    with type context = string

end

val set_allowed_addresses: Ipaddr.t list option -> unit

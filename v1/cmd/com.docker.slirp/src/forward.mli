
include Active_list.Instance
  with type context = string

val set_allowed_addresses: Ipaddr.t list option -> unit

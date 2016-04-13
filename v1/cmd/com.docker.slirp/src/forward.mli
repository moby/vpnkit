
module Make(S: Network_stack.S) : Active_list.Instance
  with type context = S.t

val set_allowed_addresses: Ipaddr.t list option -> unit

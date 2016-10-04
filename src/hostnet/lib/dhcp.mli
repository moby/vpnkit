


module Make(Netif: V1_LWT.NETWORK): sig
  type t

  val make: client_macaddr:Macaddr.t -> server_macaddr:Macaddr.t
    -> peer_ip: Ipaddr.V4.t -> local_ip:Ipaddr.V4.t
    -> extra_dns_ip:Ipaddr.V4.t list -> get_domain_search:(unit -> string list)
    -> Netif.t -> t

  val callback: t -> Cstruct.t -> unit Lwt.t
end

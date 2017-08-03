module Make  (Clock: Mirage_clock_lwt.MCLOCK) (Netif: Mirage_net_lwt.S): sig
  type t

  val make: server_macaddr:Macaddr.t
    -> peer_ip: Ipaddr.V4.t -> highest_peer_ip: Ipaddr.V4.t option
    -> local_ip:Ipaddr.V4.t
    -> extra_dns_ip:Ipaddr.V4.t list -> get_domain_search:(unit -> string list)
    -> get_domain_name:(unit -> string)
    -> Clock.t -> Netif.t -> t

  val callback: t -> Cstruct.t -> unit Lwt.t
end

module Make
    (Ip: V1_LWT.IPV4 with type prefix = Ipaddr.V4.t)
    (Udp: V1_LWT.UDPV4)
    (Resolv_conv: Sig.RESOLV_CONF)
    (Socket: Sig.SOCKETS)
    (Time: V1_LWT.TIME) : sig
  val start_reaper: unit -> unit Lwt.t
  val input: ip:Ip.t -> udp:Udp.t -> src:Ipaddr.V4.t -> dst:Ipaddr.V4.t -> src_port:int -> Cstruct.t -> unit Lwt.t
end

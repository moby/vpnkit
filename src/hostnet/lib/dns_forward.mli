module Make
    (Ip: V1_LWT.IPV4 with type prefix = Ipaddr.V4.t)
    (Udp: V1_LWT.UDPV4)
    (Resolv_conv: Sig.RESOLV_CONF) : sig
  val input: ip:Ip.t -> udp:Udp.t -> src:Ipaddr.V4.t -> dst:Ipaddr.V4.t -> src_port:int -> Cstruct.t -> unit Lwt.t
end

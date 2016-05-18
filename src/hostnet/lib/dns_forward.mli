module Make(Tcpip_stack: Sig.TCPIP)(Resolv_conv: Sig.RESOLV_CONF): sig
val input: Tcpip_stack.t -> src:Ipaddr.V4.t -> dst:Ipaddr.V4.t -> src_port:int -> Cstruct.t -> unit Lwt.t
end

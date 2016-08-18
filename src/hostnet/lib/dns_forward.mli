module Make
    (Ip: V1_LWT.IPV4 with type prefix = Ipaddr.V4.t)
    (Udp: V1_LWT.UDPV4)
    (Resolv_conv: Sig.RESOLV_CONF)
    (Socket: Sig.SOCKETS)
    (Time: V1_LWT.TIME) : sig
  val input: secondary:bool -> udp:Udp.t -> src:Ipaddr.V4.t -> dst:Ipaddr.V4.t -> src_port:int -> Cstruct.t -> unit Lwt.t
end

val choose_server: nth:int -> (Ipaddr.t * int) list -> (string * (Ipaddr.t * int)) option
(** [choose_server nth servers] chooses an upstream server to use from
    [servers]. The choice depends on which virtual server IP received the request
    (nth).  Also returns a short descriptive string to include in the logs. *)

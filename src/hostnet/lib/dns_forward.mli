module Make
    (Ip: V1_LWT.IPV4 with type prefix = Ipaddr.V4.t)
    (Udp: V1_LWT.UDPV4)
    (Resolv_conv: Sig.RESOLV_CONF)
    (Socket: Sig.SOCKETS)
    (Time: V1_LWT.TIME) : sig
  val input: nth:int -> udp:Udp.t -> src:Ipaddr.V4.t -> dst:Ipaddr.V4.t -> src_port:int -> Cstruct.t -> unit Lwt.t

  val choose_server: nth:int -> unit -> (string * (Ipaddr.t * int)) option Lwt.t
  (** [choose_server nth ()] chooses an upstream server to use from the
      currently-configured system resolver.
      The choice depends on which virtual server IP received the request
      (nth).  Also returns a short descriptive string to include in the logs. *)
end

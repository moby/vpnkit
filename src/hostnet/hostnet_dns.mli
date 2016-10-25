
module Policy(Files: Sig.FILES): Sig.DNS_POLICY
(** Global DNS configuration *)

module Make
    (Ip: V1_LWT.IPV4 with type prefix = Ipaddr.V4.t)
    (Udp: V1_LWT.UDPV4)
    (Tcp:V1_LWT.TCPV4)
    (Socket: Sig.SOCKETS)
    (Time: V1_LWT.TIME)
    (Recorder: Sig.RECORDER) : sig

  type t
  (** A DNS proxy instance with a fixed configuration *)

  val create: ?rewrite_local_ip:Ipaddr.V4.t -> Dns_forward.Config.t -> t Lwt.t
  (** Create a DNS forwarding instance based on the given configuration.
      If ?rewrite_local_ip is not None, we will rewrite DNS requests sent via
      host sockets with the IP address of 0.0.0.0 to the given IP. This is
      intended to make the resulting .pcap trace easier to read and analyse. *)

  val set_recorder: Recorder.t -> unit

  val handle_udp: t:t -> udp:Udp.t -> src:Ipaddr.V4.t -> dst:Ipaddr.V4.t -> src_port:int -> Cstruct.t -> unit Lwt.t

  val handle_tcp: t:t -> (int -> (Tcp.flow -> unit Lwt.t) option) Lwt.t

  val destroy: t -> unit Lwt.t
end

type pcap = (string * int64 option) option
(** Packet capture configuration. None means don't capture; Some (file, limit)
    means write pcap-formatted data to file. If the limit is None then the
    file will grow without bound; otherwise the file will be closed when it is
    bigger than the given limit. *)

type config = {
  peer_ip: Ipaddr.V4.t;
  local_ip: Ipaddr.V4.t;
  extra_dns_ip: Ipaddr.V4.t list;
  get_domain_search: unit -> string list;
  pcap_settings: pcap Active_config.values;
}
(** A slirp TCP/IP stack ready to accept connections *)

module Make(Config: Active_config.S)(Vmnet: Sig.VMNET)(Resolv_conv: Sig.RESOLV_CONF)(Host: Sig.HOST): sig

  val create: Config.t -> config Lwt.t
  (** Initialise a TCP/IP stack, taking configuration from the Config.t *)

  type t

  val connect: config -> Vmnet.fd -> t Lwt.t
  (** Read and write ethernet frames on the given fd *)

  val after_disconnect: t -> unit Lwt.t
  (** Waits until the stack has been disconnected *)

  val filesystem: t -> Vfs.Dir.t
  (** A virtual filesystem which exposes internal state for debugging *)
end

val print_pcap: pcap -> string

val client_macaddr: Macaddr.t

val server_macaddr: Macaddr.t

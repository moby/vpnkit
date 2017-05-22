
type pcap = (string * int64 option) option
(** Packet capture configuration. None means don't capture; Some (file, limit)
    means write pcap-formatted data to file. If the limit is None then the
    file will grow without bound; otherwise the file will be closed when it is
    bigger than the given limit. *)

type arp_table = {
  mutex: Lwt_mutex.t;
  mutable table: (Ipaddr.V4.t * Macaddr.t) list;
}

type uuid_table = {
  mutex: Lwt_mutex.t;
  table: (Uuidm.t, Ipaddr.V4.t * int) Hashtbl.t;
}

type config = {
  server_macaddr: Macaddr.t;
  peer_ip: Ipaddr.V4.t;
  local_ip: Ipaddr.V4.t;
  extra_dns_ip: Ipaddr.V4.t list;
  get_domain_search: unit -> string list;
  get_domain_name: unit -> string;
  global_arp_table: arp_table;
  client_uuids: uuid_table;
  bridge_connections: bool;
  mtu: int;
  host_names: Dns.Name.t list;
  http_intercept: bool ref;
}

(** A slirp TCP/IP stack ready to accept connections *)

module Make(Config: Active_config.S)(Vmnet: Sig.VMNET)(Dns_policy: Sig.DNS_POLICY)(Host: Sig.HOST)(Vnet : Vnetif.BACKEND) : sig

  val create: ?host_names:Dns.Name.t list -> Config.t -> config Lwt.t
  (** Initialise a TCP/IP stack, taking configuration from the Config.t *)

  type t

  val connect: config -> Vmnet.fd -> Vnet.t -> t Lwt.t
  (** Read and write ethernet frames on the given fd, connected to the specified Vnetif backend *)

  val after_disconnect: t -> unit Lwt.t
  (** Waits until the stack has been disconnected *)

  val filesystem: t -> Vfs.Dir.t
  (** A virtual filesystem which exposes internal state for debugging *)

  val diagnostics: t -> Host.Sockets.Stream.Unix.flow -> unit Lwt.t
  (** Output diagnostics in .tar format over a local Unix socket or named pipe *)

  module Debug: sig
    val get_nat_table_size: t -> int
    (** Return the number of active NAT table entries *)

    val update_dns: ?local_ip:Ipaddr.t -> ?host_names:Dns.Name.t list -> unit -> unit
    (** Update the DNS forwarder following a configuration change *)
  end
end

val print_pcap: pcap -> string

val default_server_macaddr: Macaddr.t
val default_client_macaddr: Macaddr.t

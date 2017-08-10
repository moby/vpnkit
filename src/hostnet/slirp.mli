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

(** A slirp TCP/IP stack ready to accept connections *)


type ('clock, 'vnet_switch) config = {
  server_macaddr: Macaddr.t;
  peer_ip: Ipaddr.V4.t;
  local_ip: Ipaddr.V4.t;
  highest_ip: Ipaddr.V4.t;
  extra_dns_ip: Ipaddr.V4.t list;
  get_domain_search: unit -> string list;
  get_domain_name: unit -> string;
  global_arp_table: arp_table;
  client_uuids: uuid_table;
  vnet_switch: 'vnet_switch;
  mtu: int;
  host_names: Dns.Name.t list;
  clock: 'clock;
  port_max_idle_time: int;
}

module Make
    (Config: Active_config.S)
    (Vmnet: Sig.VMNET)
    (Dns_policy: Sig.DNS_POLICY)
    (Clock: sig
       include Mirage_clock_lwt.MCLOCK
       val connect: unit -> t Lwt.t
     end)
    (Random: Mirage_random.C)
    (Vnet : Vnetif.BACKEND with type macaddr = Macaddr.t) :
sig

  val create: ?host_names:Dns.Name.t list -> Clock.t -> Vnet.t -> Config.t ->
    (Clock.t, Vnet.t) config Lwt.t
  (** Initialise a TCP/IP stack, taking configuration from the Config.t *)

  type t

  val connect: (Clock.t, Vnet.t) config -> Vmnet.fd -> t Lwt.t
  (** Read and write ethernet frames on the given fd, connected to the
      specified Vnetif backend *)

  val after_disconnect: t -> unit Lwt.t
  (** Waits until the stack has been disconnected *)

  val filesystem: t -> Vfs.Dir.t
  (** A virtual filesystem which exposes internal state for debugging *)

  val diagnostics: t -> Host.Sockets.Stream.Unix.flow -> unit Lwt.t
  (** Output diagnostics in .tar format over a local Unix socket or named pipe *)

  module Debug: sig
    val get_nat_table_size: t -> int
    (** Return the number of active NAT table entries *)

    val update_dns: ?local_ip:Ipaddr.t -> ?host_names:Dns.Name.t list ->
      Clock.t -> unit
    (** Update the DNS forwarder following a configuration change *)

    val update_http: ?http:string -> ?https:string -> ?exclude:string ->
      unit -> (unit, [`Msg of string]) result Lwt.t
    (** Update the HTTP forwarder following a configuration change *)

    val update_http_json: Ezjsonm.value ->
      unit -> (unit, [`Msg of string]) result Lwt.t
    (** Update the HTTP forwarder using the json interface *)
  end
end

val print_pcap: pcap -> string

val default_server_macaddr: Macaddr.t

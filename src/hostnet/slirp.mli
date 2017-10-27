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


type ('clock, 'vnet_switch) config

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

  val create_static: Clock.t -> Vnet.t -> Configuration.t ->
  (Clock.t, Vnet.t) config Lwt.t
  (** Initialise a TCP/IP stack, with a static configuration *)

  val create_from_active_config: Clock.t -> Vnet.t -> Configuration.t -> Config.t ->
    (Clock.t, Vnet.t) config Lwt.t
  (** Initialise a TCP/IP stack, allowing the dynamic Config.t to override
      the static Configuration.t *)

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

type pcap = (string * int64 option) option
(** Packet capture configuration. None means don't capture; Some (file, limit)
    means write pcap-formatted data to file. If the limit is None then the
    file will grow without bound; otherwise the file will be closed when it is
    bigger than the given limit. *)

module Make
    (Vmnet: Sig.VMNET)
    (Dns_policy: Sig.DNS_POLICY)
    (Clock: Mirage_clock.MCLOCK)
    (Random: Mirage_random.S)
    (Vnet : Vnetif.BACKEND with type macaddr = Macaddr.t) :
sig

  type stack
  (** A TCP/IP stack which may talk to multiple ethernet clients *)

  val create_static: Vnet.t -> Configuration.t -> stack Lwt.t
  (** Initialise a TCP/IP stack, with a static configuration *)

  type connection
  (** An ethernet connection to a stack *)

  val connect: stack -> Vmnet.fd -> connection Lwt.t
  (** Read and write ethernet frames on the given fd, connected to the
      specified Vnetif backend *)

  val after_disconnect: connection -> unit Lwt.t
  (** Waits until the stack has been disconnected *)

  val filesystem: connection -> Vfs.Dir.t
  (** A virtual filesystem which exposes internal state for debugging *)

  val diagnostics: connection -> Host.Sockets.Stream.Unix.flow -> unit Lwt.t
  (** Output diagnostics in .tar format over a local Unix socket or named pipe *)

  val pcap: connection -> Host.Sockets.Stream.Unix.flow -> unit Lwt.t
  (** Output all traffic in pcap format over a local Unix socket or named pipe *)

  module Debug: sig
    module Nat : sig
      type address = Ipaddr.t * int

      type flow = {
        inside: address;
        outside: address;
        last_use_time_ns: int64;
      }

      val get_table: connection -> flow list
      (** Return an instantaneous snapshot of the NAT table *)

      val get_max_active_flows: connection -> int
    end

    val update_dns: ?local_ip:Ipaddr.t -> ?builtin_names:(Dns.Name.t * Ipaddr.t) list ->
      unit -> unit
    (** Update the DNS forwarder following a configuration change *)

    val update_http: ?http:string -> ?https:string -> ?exclude:string
      -> ?transparent_http_ports:int list -> ?transparent_https_ports:int list
      -> unit -> (unit, [`Msg of string]) result Lwt.t
    (** Update the HTTP forwarder following a configuration change *)

    val update_http_json: Ezjsonm.value ->
      unit -> (unit, [`Msg of string]) result Lwt.t
    (** Update the HTTP forwarder using the json interface *)
  end
end

val print_pcap: pcap -> string

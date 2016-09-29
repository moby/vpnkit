module Make(Vmnet: Sig.VMNET)(Time: V1_LWT.TIME): sig
include Sig.TCPIP

type configuration

val make: client_macaddr:Macaddr.t -> server_macaddr:Macaddr.t
  -> peer_ip: Ipaddr.V4.t -> local_ip:Ipaddr.V4.t
  -> extra_dns_ip:Ipaddr.V4.t list -> get_domain_search:(unit -> string list)
  -> configuration

module Netif: sig
  type t

  val add_match: t:t -> name:string -> limit:int -> Capture.Match.t -> unit
  (** Start capturing traffic which matches a given rule *)

  val filesystem: t -> Vfs.Dir.t
  (** A virtual filesystem containing pcap-formatted data from each match *)
end

val connect:
  config:configuration -> Vmnet.t
  -> [ `Ok of (t * udpv4 list * Netif.t) | `Error of [ `Msg of string ] ] Lwt.t
end

module Make(Vmnet: Sig.VMNET)(Time: V1_LWT.TIME): sig
include Sig.TCPIP

type configuration

val make: client_macaddr:Macaddr.t -> server_macaddr:Macaddr.t
  -> peer_ip: Ipaddr.V4.t -> local_ip:Ipaddr.V4.t
  -> extra_dns_ip:Ipaddr.V4.t list -> domain_search:string list
  -> configuration

val connect:
  config:configuration -> Vmnet.t
  -> [ `Ok of (t * udpv4 list) | `Error of [ `Msg of string ] ] Lwt.t
end

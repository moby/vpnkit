
module type S = sig
  include V1_LWT.STACKV4

  type configuration

  val make: peer_ip: Ipaddr.V4.t -> local_ip:Ipaddr.V4.t -> configuration

  val connect:
    config:configuration -> Ppp.t
    -> [ `Ok of t | `Error of [ `Msg of string ] ] Lwt.t

  module TCPV4_half_close : Mirage_flow_s.SHUTDOWNABLE
    with type flow = TCPV4.flow
end

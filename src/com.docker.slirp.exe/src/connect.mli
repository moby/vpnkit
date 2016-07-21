open Hostnet

module Make(Host: Sig.HOST): sig
  include Sig.Connector

  val set_port_forward_addr: Hvsock.sockaddr -> unit

  val set_max_connections: int option -> unit
end

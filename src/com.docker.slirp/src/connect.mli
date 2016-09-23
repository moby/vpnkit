open Hostnet

module Make_unix(Host: Sig.HOST): sig
  include Sig.Connector

  val vsock_path: string ref
end

module Make_hvsock(Host: Sig.HOST): sig
  include Sig.Connector

  val set_port_forward_addr: Hvsock.sockaddr -> unit
end

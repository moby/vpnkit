module Unix: sig
  include Sig.Connector

  val vsock_path: string ref
end

module Hvsock: sig
  include Sig.Connector

  val set_port_forward_addr: Hvsock.Af_hyperv.sockaddr -> unit
end

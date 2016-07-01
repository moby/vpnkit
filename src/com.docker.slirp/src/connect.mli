open Hostnet

module Make(Socket: Sig.SOCKETS): sig
  include Sig.Connector

  val vsock_path: string ref
end

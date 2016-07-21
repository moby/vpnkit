open Hostnet

module Make(Host: Sig.HOST): sig
  include Sig.Connector

  val set_max_connections: int option -> unit

  val vsock_path: string ref
end

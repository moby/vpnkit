val vsock_path: string ref

include Hostnet.Sig.Connector with type port = Hostnet.Forward.Port.t

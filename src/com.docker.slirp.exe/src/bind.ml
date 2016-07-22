open Hostnet

module Make(Socket: Sig.SOCKETS) = struct
  include Socket
end

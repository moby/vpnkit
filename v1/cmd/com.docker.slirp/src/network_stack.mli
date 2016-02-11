
module type S = sig
  include V1_LWT.STACKV4

  module TCPV4_half_close : Mirage_flow_s.SHUTDOWNABLE
    with type flow = TCPV4.flow
end

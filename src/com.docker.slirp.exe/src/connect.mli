open Hostnet

module Make(Time: V1_LWT.TIME)(Main: Lwt_hvsock.MAIN): Sig.Connector

val set_port_forward_addr: Hvsock.sockaddr -> unit

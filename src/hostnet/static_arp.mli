(** A fixed ARP table: since we control the network there's no need to
    rely on the dynamic version which can fail with `No_route_to_host` if
    the other side doesn't respond *)

module Make(Ethif: Ethernet.S): sig
  include Arp.S

  type ethif = Ethif.t

  val connect:
    table:(Ipaddr.V4.t * Macaddr.t) list -> ethif -> t
    (** Construct a static ARP table *)
end

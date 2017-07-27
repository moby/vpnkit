(** A fixed ARP table: since we control the network there's no need to
    rely on the dynamic version which can fail with `No_route_to_host` if
    the other side doesn't respond *)

module Make(Ethif: Mirage_protocols_lwt.ETHIF): sig
  include Mirage_protocols_lwt.ARP

  type ethif = Ethif.t

  val connect:
    table:(ipaddr * macaddr) list -> ethif -> t
    (** Construct a static ARP table *)
end

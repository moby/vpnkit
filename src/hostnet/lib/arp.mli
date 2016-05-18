(** A fixed ARP table: since we control the network there's no need to
    rely on the dynamic version which can fail with `No_route_to_host` if
    the other side doesn't respond *)

module Make(Ethif: V1_LWT.ETHIF): sig
  include V1_LWT.ARP

  type table = (ipaddr * macaddr) list

  type ethif = Ethif.t

  val connect:
    table:table -> ethif
    -> [ `Ok of t | `Error of error ] Lwt.t
  (** Construct a static ARP table *)
end

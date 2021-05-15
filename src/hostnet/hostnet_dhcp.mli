module Make  (Clock: Mirage_clock.MCLOCK) (Netif: Mirage_net.S): sig
  type t

  val make: configuration:Configuration.t -> Netif.t -> t
  (** Create a DHCP server. *)

  val callback: t -> Cstruct.t -> unit Lwt.t
end

val update_global_configuration: Configuration.Dhcp_configuration.t option -> unit
(** Update the global DHCP configuration: gateway IP, search domains etc *)
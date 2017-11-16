module Make  (Clock: Mirage_clock_lwt.MCLOCK) (Netif: Mirage_net_lwt.S): sig
  type t

  val make: configuration:Configuration.t -> Clock.t -> Netif.t -> t

  val callback: t -> Cstruct.t -> unit Lwt.t
end

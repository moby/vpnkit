module Make(Netif: Mirage_net.S) : sig
  include Mirage_net.S

  (** A simple ethernet multiplexer/demultiplexer

      An instance has an underlying ethernet NETWORK which it receives
      packets from. If a packet matches a rule associated with a downstream
      port, it is sent there. Packets which don't match any rules are sent
      to the default callback for processing. All transmissions from downstream
      ports are sent on the underlying network.

      The default callback (set by [listen]) acts as the control-path: it's function
      is to accept flows and set up new rules.

  *)

  val connect: Netif.t -> (t, error) result Lwt.t
  (** Connect a multiplexer/demultiplexer and return a [t] which behaves like
      a V1.NETWORK representing the multiplexed end. *)

  type rule = Ipaddr.V4.t
  (** We currently support matching on IPv4 destination addresses only *)

  module Port : Mirage_net.S
  (** A network which receives all the traffic matching a specific rule *)

  val port: t -> rule -> Port.t
  (** Given a rule, create a network which will receive traffic matching the
      rule. *)

  val remove: t -> rule -> unit
  (** Given a rule, remove the associated port if one exists *)

  val filesystem: t -> Vfs.File.t
  (** A virtual filesystem for debugging *)
end

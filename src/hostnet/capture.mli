module Make(Input: Sig.VMNET): sig
  include Sig.VMNET
  include Sig.RECORDER with type t := t

  val connect: Input.t -> t
  (** Capture traffic from a network, match against a set of capture rules
      and keep a limited amount of the most recent traffic that matches. *)

  type rule
  (** A rule matches some packets *)

  val add_match: t:t -> name:string -> limit:int -> snaplen:int ->
    predicate:(Frame.t -> bool) -> rule
  (** Start capturing traffic which matches a given rule *)

  val to_pcap: rule -> (Cstruct.t list) Lwt_stream.t
  (** Given a rule return a pcap formatted stream of packets matching the rule *)

  val filesystem: t -> Vfs.Dir.t
  (** A virtual filesystem containing pcap-formatted data from each match *)
end

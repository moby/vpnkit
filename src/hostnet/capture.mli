module Make(Input: Sig.VMNET): sig
  include Sig.VMNET
  include Sig.RECORDER with type t := t

  val connect: Input.t -> t
  (** Capture traffic from a network, match against a set of capture rules
      and keep a limited amount of the most recent traffic that matches. *)

  val add_match: t:t -> name:string -> limit:int -> snaplen:int ->
    predicate:(Frame.t -> bool) -> unit
  (** Start capturing traffic which matches a given rule *)

  val filesystem: t -> Vfs.Dir.t
  (** A virtual filesystem containing pcap-formatted data from each match *)
end

module Make(Input: Sig.VMNET): sig
  include Sig.VMNET

  val connect: limit:int -> Input.t
    -> [ `Ok of t | `Error of error ] Lwt.t
  (** Capture traffic from a network and keep a fixed amount of it
      (measured in bytes) *)

end

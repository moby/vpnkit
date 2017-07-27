module Make(Input: Sig.VMNET): sig
  include Sig.VMNET

  val connect:
    valid_subnets:Ipaddr.V4.Prefix.t list
    -> valid_sources:Ipaddr.V4.t list -> Input.t
    -> t
    (** Construct a filtered ethernet network which removes IP packets whose
        source IP is not in [valid_sources] *)
end

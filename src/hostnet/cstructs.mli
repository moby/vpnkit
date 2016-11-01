
(** A subset of the Cstruct signature with type t = Cstruct.t list

    This should be replaced with another parser, perhaps angstrom? *)

type t = Cstruct.t list
(** Data stored as a list of fragments *)

val shift: t -> int -> t

val len: t -> int

val get_uint8: t -> int -> int

module BE: sig
  val get_uint16: t -> int -> int
  val get_uint32: t -> int -> int32
end

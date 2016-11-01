
(** A subset of the Cstruct signature with type t = Cstruct.t list

    This should be replaced with another parser, perhaps angstrom? *)

type t = Cstruct.t list
(** Data stored as a list of fragments *)

val to_string: t -> string

val shift: t -> int -> t

val len: t -> int

val sub: t -> int -> int -> t

val get_uint8: t -> int -> int

val to_cstruct: t -> Cstruct.t
(** Returns a contiguous Cstruct.t, which may or may not involve a copy. *)

module BE: sig
  val get_uint16: t -> int -> int
  val get_uint32: t -> int -> int32
end

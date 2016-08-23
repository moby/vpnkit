
type t = {
  resolvers: (Ipaddr.t * int) list;
  search: string list;
}

val to_string: t -> string

val parse_resolvers: string -> t option
(** [parse_resolvers data] parses DNS resolvers stored in a string *)

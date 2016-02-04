
type t
(** The client requests one of these *)

val to_string: t -> string
val of_string: string -> (t, [ `Msg of string ]) Result.result

type context = Tcpip_stack.t
(** The context in which a [t] is [start]ed, for example a TCP/IP stack *)

val start: context -> t -> (t, [ `Msg of string ]) Result.result Lwt.t

val stop: t -> unit Lwt.t

type key
(** Some unique primary key *)

module Map: Map.S with type key = key

val get_key: t -> key

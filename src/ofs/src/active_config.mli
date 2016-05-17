type t

val create: ?username:string -> string -> string -> t
(** [create ?username proto address] creates an active configuration
    system backed by the database at [proto:address]. *)

type 'a values = Value of ('a * ('a values) Lwt.t)
(** An infinite stream of values of type ['a] *)

val hd: 'a values -> 'a
(** The first element of a stream of values *)

val tl: 'a values -> 'a values Lwt.t
(** The rest of a stream of values, after the first element *)

val map: ('a -> 'b Lwt.t) -> 'a values -> 'b values Lwt.t
(** Transform an infinite stream of values *)

type path = string list

val string_option: t -> path -> string option values Lwt.t
(** The stream of optional string values at [path] *)

val string: t -> default:string -> path -> string values Lwt.t
(** The stream of string values at [path] *)

val int: t -> default:int -> path -> int values Lwt.t
(** The stream of int values at [path] *)

val bool: t -> default:bool -> path -> bool values Lwt.t
(** The stream of bool values at [path] *)

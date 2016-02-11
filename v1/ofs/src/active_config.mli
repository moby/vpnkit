type t

val create: ?username:string -> string -> string -> t Lwt.t
(** [create ?username proto address] creates an active configuration
    system backed by the database at [proto:address]. *)

type 'a values
(** An infinite stream of values of type ['a] *)

val hd: 'a values -> 'a
(** The first element of a stream of values *)

val tl: 'a values -> 'a values Lwt.t
(** The rest of a stream of values, after the first element *)

type path = string list

val string: t -> path -> string option values Lwt.t
(** The stream of string values at [path] *)

val int: t -> path -> int option values Lwt.t
(** The stream of int values at [path] *)

val bool: t -> path -> bool option values Lwt.t
(** The stream of bool values at [path] *)

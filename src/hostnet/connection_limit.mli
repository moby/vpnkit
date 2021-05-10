val set_max : int option -> unit
(** [set_max None] disables connection limits.
    [set_max (Some x)] sets the connection limit to [x] *)

val register_no_limit : string -> int
(** [register_no_limit description] registers a connection and returns an ID, ignoring any limit *)

val register : string -> (int, [ `Msg of string ]) result
(** [register description] attempts to register a connection and returns an ID if we haven't
    reached the connection limit. *)

val deregister : int -> unit
(** [deregister id] deregister the connection with ID [id] *)

(** For debugging, testing and diagnostics: *)

val connections : unit -> Vfs.File.t
(** [connections ()] returns a snapshot of the active connections for diagnostics. *)

val get_num_connections : unit -> int
(** [get_num_connections ()] returns the current number of active connections *)

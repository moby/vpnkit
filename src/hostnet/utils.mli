
val somaxconn: int ref (* can be overriden by the command-line *)

val rtlGenRandom: int -> bytes option
(** [rtlGenRandom len] returns [len] bytes of secure random data on Windows.
    Returns None if called on non-Windows platforms *)

val setSocketTTL: Unix.file_descr -> int -> unit
(** [setSocketTTL s ttl] sets the TTL on the socket [s] to [ttl] *)

val cstruct_send: Unix.file_descr -> Cstruct.t -> int
(** [cstruct_send fd c] can be used to send a datagram *)

val cstruct_recv: Unix.file_descr -> Cstruct.t -> int
(** [cstruct_recv fd c] can be used to receive a datagram *)
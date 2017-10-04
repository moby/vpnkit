
val somaxconn: int ref (* can be overriden by the command-line *)

val rtlGenRandom: int -> bytes option
(** [rtlGenRandom len] returns [len] bytes of secure random data on Windows.
    Returns None if called on non-Windows platforms *)

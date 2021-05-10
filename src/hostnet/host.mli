include Sig.HOST

val start_background_gc : int option -> unit
(** [start_background_gc interval] starts a background thread which compacts
    the heap every [interval] seconds. An immediate compact can be triggered
    by sending SIGUSR1 *)

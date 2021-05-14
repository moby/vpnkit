
(** Implements the core of the unique name probing part of a Multicast DNS (mDNS) responder. *)

(** The internal data structure representing the of the probing part of an mDNS responder. *)
type state

(** A DNS packet to be sent with its destination IP address and UDP port number. *)
type datagram = Packet.t * Ipaddr.V4.t * int

(** The I/O action that the caller of this module must take. *)
type action =
  | Nothing  (** The protocol is idle because all names have been confirmed unique. *)
  | ToSend of datagram  (** The caller shall send the specified [datagram]. *)
  | Delay of float  (** The caller shall wait for the specified duration in seconds. *)
  | Continue  (** The caller should invoke [do_probe] again. *)
  | NotReady  (** The call was unexpected. This may indicate a bug in the caller, and should be logged. *)
  | Stop  (** [stop] has been called. *)

(** Initialises a new mDNS probe protocol. *)
val new_state : Loader.db -> state

(** Marks a Name.t as unique. The name will be included in the next probe cycle. *)
val add_name : state -> Name.t -> state

(** Initiates the probe protocol and returns the I/O action that the caller should take. *)
val do_probe : state -> state * action

(** After completing a [ToSend] action, call this function to continue the probe protocol. *)
val on_send_complete : state -> state * action

(** After completing a [Delay] action, call this function to continue the probe protocol. *)
val on_delay_complete : state -> state * action

(** Returns [true] if the first probe cycle has completed successfully. *)
val is_first_complete : state -> bool

(** Indicates whether the received datagram caused a restart of the probe cycle due to a conflict. *)
type conflict =
  | NoConflict  (** No conflict occurred. *)
  | ConflictRestart  (** A conflict occurred. The caller should interrupt any [Delay] action that is currently executing, if possible. *)

(** Call this function when an mDNS response packet is received, in order to check for conflicting resource records. *)
val on_response_received : state -> Packet.t -> state * conflict

(** Call this function when an mDNS query packet is received, in order to check for simultaneous probe conflicts. *)
val on_query_received : state -> Packet.t -> Packet.t -> Packet.t * state * conflict

(** Returns [true] if the name has been confirmed unique (probed successfully).
    This is intended for controlling the cache flush bit. *)
val is_confirmed : state -> Name.t -> bool

(** Stops executing the protocol. *)
val stop : state -> state

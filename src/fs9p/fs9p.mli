(** Expose a VFS directory over 9p. *)

(** The server signature. *)
module type S = sig
  type flow
  (** The type for communication "channels" between the clients and
      the server. *)

  val accept :
    root:Vfs.Dir.t -> msg:string -> flow -> unit Protocol_9p.Error.t Lwt.t
  (** [accept ~root f] accepts connection on [f], processs requests
      and returns when the connection has beenn closed. *)
end

module Make (Flow : Mirage_flow.S) : S with type flow = Flow.flow
(** Server builder. *)

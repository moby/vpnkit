module Make (Flow : Mirage_flow.S) : sig
  type flow

  module Channel : sig
    type channel

    val connect : flow -> Frame.Destination.t -> channel Lwt.t

    include Mirage_flow_combinators.SHUTDOWNABLE with type flow = channel

    val read_into: channel -> Cstruct.t -> (unit Mirage_flow.or_eof, error) result Lwt.t
  end

  type listen_cb = Channel.flow -> Frame.Destination.t -> unit Lwt.t

  val connect : Flow.flow -> string -> listen_cb -> flow

  val is_running : flow -> bool
  (** [is_running flow] is true if the dispatcher thread is still running. *)

  val disconnect: flow -> unit Lwt.t
  (** [disconnect flow] disconnects the underlying flow *)
end

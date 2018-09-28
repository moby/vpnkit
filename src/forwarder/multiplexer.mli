module Make (Flow : Mirage_flow_lwt.S) : sig
  type flow

  module Channel : sig
    type channel

    val connect : flow -> Frame.Destination.t -> channel Lwt.t

    include Mirage_flow_lwt.SHUTDOWNABLE with type flow = channel
  end

  type listen_cb = Channel.flow -> Frame.Destination.t -> unit Channel.io

  val connect : Flow.flow -> string -> listen_cb -> flow
end

module Make(C: Sig.CONN): sig
  (** Accept connections and talk to clients via the vmnetd protocol, exposing
      the packets as a Mirage NETWORK interface *)

  type fd = C.flow

  include Mirage_net_lwt.S with type buffer = Cstruct.t

  val after_disconnect: t -> unit Lwt.t
  (** [after_disconnect connection] resolves after [connection] has
        disconnected. *)

  val add_listener: t -> (Cstruct.t -> unit Lwt.t) -> unit

  val of_fd:
    client_macaddr_of_uuid:(Uuidm.t -> Macaddr.t Lwt.t) ->
    server_macaddr:Macaddr.t -> mtu:int -> C.flow ->
    (t, [`Msg of string]) result Lwt.t
  (** [of_fd ~client_macaddr_of_uuid ~server_macaddr ~mtu fd]
      negotiates with the client over [fd]. The server uses
      [client_macaddr_of_uuid] to create a source address for the
      client's ethernet frames based on a uuid supplied by the
      client. The server uses [server_macaddr] as the source address
      of all its ethernet frames and sets the MTU to [mtu]. *)

  val client_of_fd: uuid:Uuidm.t -> server_macaddr:Macaddr.t -> C.flow ->
    (t, [`Msg of string]) result Lwt.t

  val start_capture: t -> ?size_limit:int64 -> string -> unit Lwt.t
  (** [start_capture t ?size_limit filename] closes any existing pcap
      capture file and starts capturing to [filename]. If
      [?size_limit] is provided then the file will be automatically
      closed after the given number of bytes are written -- this is to
      avoid forgetting to close the file and filling up your storage
      with capture data. *)

  val stop_capture: t -> unit Lwt.t
  (** [stop_capture t] stops any in-progress capture and closes the file. *)

  val get_client_uuid: t -> Uuidm.t

  val get_client_macaddr: t -> Macaddr.t

end

module Init : sig
  type t

  val to_string: t -> string
  val sizeof: int
  val default: t

  val marshal: t -> Cstruct.t -> Cstruct.t
  val unmarshal: Cstruct.t -> t * Cstruct.t
end

module Command : sig

  type t =
    | Ethernet of Uuidm.t (* 36 bytes *)
    | Bind_ipv4 of Ipaddr.V4.t * int * bool

  val to_string: t -> string
  val sizeof: int

  val marshal: t -> Cstruct.t -> Cstruct.t
  val unmarshal: Cstruct.t -> (t * Cstruct.t, [ `Msg of string ]) result
end

module type CONN = sig
  include Mirage_flow_s.SHUTDOWNABLE

  val read_into: flow -> Cstruct.t -> [ `Eof | `Ok of unit ] Lwt.t
  (** Completely fills the given buffer with data from [fd] *)
end

module Make(C: CONN): sig
(** Accept connections and talk to clients via the vmnetd protocol, exposing
    the packets as a Mirage NETWORK interface *)

type fd = C.flow

include V1_LWT.NETWORK
  with type buffer = Cstruct.t

val add_listener: t -> (Cstruct.t -> unit Lwt.t) -> unit

val of_fd: client_macaddr:Macaddr.t -> server_macaddr:Macaddr.t -> C.flow -> [ `Ok of t | `Error of [ `Msg of string ] ] Lwt.t
(** [of_fd ~client_macaddr ~server_macaddr fd] negotiates with the client over
    [fd]. The client uses [client_macaddr] as the source address of all its ethernet
    frames. The server uses [server_macaddr] as the source address of all its
    ethernet frames. *)

val client_of_fd: client_macaddr:Macaddr.t -> server_macaddr:Macaddr.t -> C.flow -> [ `Ok of t | `Error of [ `Msg of string ] ] Lwt.t

val start_capture: t -> ?size_limit:int64 -> string -> unit Lwt.t
(** [start_capture t ?size_limit filename] closes any existing pcap capture
    file and starts capturing to [filename]. If [?size_limit] is provided
    then the file will be automatically closed after the given number of
    bytes are written -- this is to avoid forgetting to close the file and
    filling up your storage with capture data. *)

val stop_capture: t -> unit Lwt.t
(** [stop_capture t] stops any in-progress capture and closes the file. *)
end

module Init : sig
  type t

  val to_string: t -> string
  val sizeof: int
  val default: t

  val marshal: t -> Cstruct.t -> Cstruct.t
  val unmarshal: Cstruct.t -> [ `Ok of t * Cstruct.t  | `Error of [ `Msg of string ]]
end

module Command : sig

  type t =
    | Ethernet of string (* 36 bytes *)
    | Bind_ipv4 of Ipaddr.V4.t * int * bool

    val to_string: t -> string
    val sizeof: int

    val marshal: t -> Cstruct.t -> Cstruct.t
    val unmarshal: Cstruct.t -> [ `Ok of t * Cstruct.t  | `Error of [ `Msg of string ]]
end

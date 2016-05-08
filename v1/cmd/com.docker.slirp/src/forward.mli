
module type Connector = sig

  module Port: sig
    type t

    val of_string: string -> (t, [> `Msg of string]) Result.result
    val to_string: t -> string
  end

  val connect: Port.t -> Lwt_unix.file_descr Lwt.t
end

module Make(Connector: Connector) : sig
  include Active_list.Instance
    with type context = string

  val set_allowed_addresses: Ipaddr.t list option -> unit
end

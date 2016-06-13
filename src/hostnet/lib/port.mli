val bind: Ipaddr.V4.t -> int -> bool
  -> (Lwt_unix.file_descr list, [> `Msg of string ]) Result.result Lwt.t
(** [bind local_ip local_port stream] binds a socket on [local_ip:local_port].
    If [stream] then the socket is SOCK_STREAM, otherwise SOCK_DGRAM. *)

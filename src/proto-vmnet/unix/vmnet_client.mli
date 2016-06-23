type t
(** A negotiated connection *)

val of_fd: Lwt_unix.file_descr -> [ `Ok of t | `Error of [ `Msg of string ] ] Lwt.t

val bind_ipv4: t -> (Ipaddr.V4.t * int * bool) -> [ `Ok of Unix.file_descr | `Error of [ `Msg of string ]] Lwt.t

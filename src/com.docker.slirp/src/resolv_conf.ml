open Lwt
open Dns

let get () =
  Dns_resolver_unix.create () (* re-read /etc/resolv.conf *)
  >>= function
  | { Dns_resolver_unix.servers } -> Lwt.return servers

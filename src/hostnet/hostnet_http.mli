module Exclude: sig
  type t
  (** A request destination which should bypass the proxy *)

  val of_string: string -> t
  val to_string: t -> string

  val matches: string -> t -> bool
  (** [matches host_or_ip excludes] is true if [host_or_ip] matches
      the excludes rules and should bypass the proxy. *)
end

module Make
    (Ip: Mirage_protocols.IPV4)
    (Udp: Mirage_protocols.UDPV4)
    (Tcp: Mirage_flow_combinators.SHUTDOWNABLE)
    (Socket: Sig.SOCKETS)
    (Dns_resolver: Sig.DNS) :
sig

  type t
  (** An HTTP proxy instance with a fixed configuration *)

  val to_string: t -> string

  val create: ?http:string -> ?https:string -> ?exclude:string
    -> ?transparent_http_ports:int list -> ?transparent_https_ports:int list
    -> unit ->
    (t, [`Msg of string]) result Lwt.t
  (** Create a transparent HTTP forwarding instance which forwards
      HTTP to the proxy [http], HTTPS to the proxy [https] or connects
      directly if the URL matches [exclude]. *)

  val of_json: Ezjsonm.value -> (t, [`Msg of string]) result Lwt.t
  (** [of_json json] decodes [json] into a proxy configuration *)

  val to_json: t -> Ezjsonm.t
  (** [to_json t] encodes [t] into json *)

  val transparent_proxy_handler:
    localhost_names:Dns.Name.t list ->
    localhost_ips:Ipaddr.t list ->
    dst:(Ipaddr.V4.t * int) -> t:t ->
    (int -> (Tcp.flow -> unit Lwt.t) option) Lwt.t option
  (** Intercept outgoing HTTP flows and redirect to the upstream proxy
      if one is defined. *)

  val explicit_proxy_handler:
    localhost_names:Dns.Name.t list ->
    localhost_ips:Ipaddr.t list ->
    dst:(Ipaddr.V4.t * int) -> t:t ->
    (int -> (Tcp.flow -> unit Lwt.t) option) Lwt.t option
  (** Intercept outgoing HTTP proxy flows and if an upstream proxy is
      defined, redirect to it, otherwise implement the proxy function
      ourselves. *)

end

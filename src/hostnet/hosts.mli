val default_etc_hosts_path: string
(** Default path where /etc/hosts should be on this machine *)

val etc_hosts: (string * Ipaddr.t) list ref
(** The current contents of the hosts file *)

val of_string: string -> (string * Ipaddr.t) list
(** Parse the contents of a hosts file *)

module Make(Files: Sig.FILES): sig

  type watch

  val watch: ?path:string -> unit -> (watch, [ `Msg of string ]) result Lwt.t
  (** Start watching the hosts file, updating the [etc_hosts] binding in the
      background. The [?path] argument allows the location of the hosts file
      to be overriden. *)

  val unwatch: watch -> unit Lwt.t
  (** Stop watching the hosts file *)

end

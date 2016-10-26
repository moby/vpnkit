module type FLOW_CLIENT = sig
  include Mirage_flow_s.SHUTDOWNABLE

  type address

  val connect: ?read_buffer_size:int -> address
    -> flow Error.t
  (** [connect address] creates a connection to [address] and returns
      he connected flow. *)

  val read_into: flow -> Cstruct.t -> [ `Eof | `Error of error | `Ok of unit ] Lwt.t
  (** Completely fills the given buffer with data from [fd] *)
end

module type FLOW_SERVER = sig
  type server
  (* A server bound to some address *)

  type address

  val of_bound_fd: ?read_buffer_size:int -> Unix.file_descr -> server
  (** Create a server from a file descriptor bound to a Unix domain socket
      by some other process and passed to us. *)

  val bind: address -> server Lwt.t
  (** Bind a server to an address *)

  val getsockname: server -> address
  (** Query the address the server is bound to *)

  type flow

  val listen: server -> (flow -> unit Lwt.t) -> unit
  (** Accept connections forever, calling the callback with each one.
      Connections are closed automatically when the callback finishes. *)

  val shutdown: server -> unit Lwt.t
  (** Stop accepting connections on the given server *)
end


module type DATAGRAM = sig

  type address

  type reply = Cstruct.t -> unit Lwt.t

  val input: ?userdesc:string -> oneshot:bool -> reply:reply -> src:address -> dst:address -> payload:Cstruct.t -> unit -> unit Lwt.t

  val get_nat_table_size: unit -> int
  (** Return the current number of allocated NAT table entries *)

end


module type SOCKETS = sig
  (* An OS-based BSD sockets implementation *)

  val set_max_connections: int option -> unit
  (** Set the maximum number of connections we permit ourselves to use. This
      is to prevent starving global OS resources, particularly on OSX *)

  (** TODO: hide these by refactoring Hyper-V sockets stuff *)
  val register_connection: string -> int Lwt.t
  val deregister_connection: int -> unit
  val connections: Vfs.Dir.t
  (** A filesystem which allows the connections to be introspected *)

  module Datagram: sig

    type address = Ipaddr.t * int

    include DATAGRAM
      with type address := address

    module Udp: sig
      type address = Ipaddr.t * int

      include FLOW_CLIENT
        with type address := address

      include FLOW_SERVER
        with type address := address
         and type flow := flow

      val recvfrom: server -> Cstruct.t -> (int * address) Lwt.t

      val sendto: server -> address -> Cstruct.t -> unit Lwt.t
    end
  end
  module Stream: sig
    module Tcp: sig
      type address = Ipaddr.t * int

      include FLOW_CLIENT
        with type address := address

      include FLOW_SERVER
        with type address := address
         and type flow := flow
    end

    module Unix: sig
      type address = string

      include FLOW_CLIENT
        with type address := address

      include FLOW_SERVER
        with type address := address
        and type flow := flow

      val unsafe_get_raw_fd: flow -> Unix.file_descr
      (** Return the underlying fd. This is intended for careful integration
          with 3rd party libraries. Don't use this fd at the same time as the
          flow. *)

    end
  end
end

module type FILES = sig
  (** An OS-based file reading implementation *)

  val read_file: string -> string Error.t
  (** Read a whole file into a string *)

  type watch

  val watch_file: string -> (unit -> unit) -> (watch, [ `Msg of string ]) Result.result
  (** [watch_file path callback] executes [callback] whenever the contents of
      [path] may have changed. *)

  val unwatch: watch -> unit
  (** [unwatch watch] stops watching the path(s) associated with [watch] *)
end

module type HOST = sig
  (** The Host interface *)

  module Sockets: sig
    (** User-space socket connections *)
    include SOCKETS
  end

  module Files: sig
    include FILES
  end

  module Time: V1_LWT.TIME

  module Main: sig
    val run: unit Lwt.t -> unit
    (** Run the main event loop *)

    val run_in_main: (unit -> 'a Lwt.t) -> 'a
    (** Run the function in the main thread *)
  end
end

module type VMNET = sig
  (** A virtual ethernet link to the VM *)

  include V1_LWT.NETWORK

  val add_listener: t -> (Cstruct.t -> unit Lwt.t) -> unit
  (** Add a callback which will be invoked in parallel with all received packets *)

  val after_disconnect: t -> unit Lwt.t
  (** Waits until the network has disconnected *)

  type fd

  val of_fd: client_macaddr:Macaddr.t -> server_macaddr:Macaddr.t
    -> fd -> t Error.t

  val start_capture: t -> ?size_limit:int64 -> string -> unit Lwt.t

  val stop_capture: t -> unit Lwt.t
end

module type DNS_POLICY = sig
  (** Policy settings

    DNS configuration is taken from 4 places, lowest to highest priority:

    - 0: a built-in default of the Google public DNS servers
    - 1: a default configuration (from a command-line argument or a configuration
      file)
    - 2: the `/etc/resolv.conf` file if present
    - 3: the database key `slirp/dns`

    If configuration with a higher priority is found then it completely overrides
    lower priority configuration.
  *)

  type priority = int (** higher is more important *)

  val add: priority:priority -> config:Dns_forward.Config.t -> unit
  (** Add some configuration at the given priority level *)

  val remove: priority:priority -> unit
  (** Remove the configuration at the given priority level *)

  val config: unit -> Dns_forward.Config.t
  (** Return the currently active DNS configuration *)
end

module type RECORDER = sig
  (** Allow ethernet packets to be recorded *)

  type t

  val record: t -> Cstruct.t list -> unit
  (** Inject a packet and record it if it matches a rule. This is intended for
      debugging: the packet will not be transmitted to the underlying network. *)
end

module type Connector = sig
  (** Make connections into the VM *)

  include FLOW_CLIENT

  val connect: unit -> flow Lwt.t
  (** Connect to the port multiplexing service in the VM *)
end

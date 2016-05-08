(*
 * Copyright (C) 2016 David Scott <dave.scott@docker.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)

module type VMNET = sig
  (** A virtual ethernet link to the VM *)

  include V1_LWT.NETWORK

  val add_listener: t -> (Cstruct.t -> unit Lwt.t) -> unit
  (** Add a callback which will be invoked in parallel with all received packets *)

end

module type TCPIP = sig
  (** A TCP/IP stack *)

  include V1_LWT.STACKV4

  module TCPV4_half_close : Mirage_flow_s.SHUTDOWNABLE
    with type flow = TCPV4.flow
end

module type RESOLV_CONF = sig
  (** The system DNS configuration *)

  val get : unit -> (Ipaddr.t * int) list Lwt.t
end


module type Connector = sig
  (** Make connections into the VM *)

  module Port: sig
    type t
    (** A protocol-specific port id, e.g. a virtio-vsock int32 *)

    val of_string: string -> (t, [> `Msg of string]) Result.result
    val to_string: t -> string
  end

  val connect: Port.t -> Lwt_unix.file_descr Lwt.t
  (** Connect to the given port on the VM *)
end

module type Binder = sig
  (** Bind local ports *)

  val bind: Ipaddr.V4.t -> int -> bool -> (Lwt_unix.file_descr, [> `Msg of string]) Result.result Lwt.t
  (** [bind local_ip local_port stream] binds [local_ip:local_port] with
      either a SOCK_STREAM if [stream] is true, or SOCK_DGRAM otherwise *)
end

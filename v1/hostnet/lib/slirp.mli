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

type pcap = (string * int64 option) option
(** Packet capture configuration. None means don't capture; Some (file, limit)
    means write pcap-formatted data to file. If the limit is None then the
    file will grow without bound; otherwise the file will be closed when it is
    bigger than the given limit. *)

module Make(Vmnet: Sig.VMNET)(Resolv_conv: Sig.RESOLV_CONF): sig

  type t = {
    peer_ip: Ipaddr.V4.t;
    local_ip: Ipaddr.V4.t;
    pcap_settings: pcap Active_config.values;
  }
  (** A slirp TCP/IP stack ready to accept connections *)

  val create: Active_config.t -> t Lwt.t
  (** Initialise a TCP/IP stack, taking configuration from the Active_config.t *)

  val connect: t -> Vmnet.fd -> unit Lwt.t
  (** Read and write ethernet frames on the given fd *)
end

val print_pcap: pcap -> string

val client_macaddr: Macaddr.t

val server_macaddr: Macaddr.t

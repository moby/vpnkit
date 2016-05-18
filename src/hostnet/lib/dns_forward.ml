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
open Lwt
open Dns

let src =
  let src = Logs.Src.create "dns" ~doc:"Resolve DNS queries on the host" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module OptionThread = struct
  let (>>=) m f = m >>= function
    | None -> Lwt.return_none
    | Some x -> f x
end

let string_of_dns buf =
  let len = Cstruct.len buf in
  let buf = Dns.Buf.of_cstruct buf in
  match Dns.Protocol.Server.parse (Dns.Buf.sub buf 0 len) with
  | None ->
    Printf.sprintf "Unparsable DNS packet length %d" len
  | Some request ->
    Dns.Packet.to_string request

module Make(Tcpip_stack: Sig.TCPIP)(Resolv_conf: Sig.RESOLV_CONF) = struct

let input s ~src ~dst ~src_port buf =
  if List.mem dst (Tcpip_stack.IPV4.get_ip (Tcpip_stack.ipv4 s)) then begin

  let src_str = Ipaddr.V4.to_string src in
  let dst_str = Ipaddr.V4.to_string dst in

  Log.debug (fun f -> f "DNS %s:%d -> %s %s" src_str src_port dst_str (string_of_dns buf));

  (* Re-read /etc/resolv.conf on every request. This ensures that
     changes to DNS on sleep/resume or switching networks are reflected
     immediately. The file is very small, and parsing it shouldn't be
     too slow. *)
  Resolv_conf.get ()
  >>= function
  | (Ipaddr.V4 dst, dst_port) :: _ -> begin
    let remote_sockaddr = Unix.ADDR_INET(Unix.inet_addr_of_string @@ Ipaddr.V4.to_string dst, dst_port) in

    let fd = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_DGRAM 0 in
    Lwt_unix.bind fd (Lwt_unix.ADDR_INET(Unix.inet_addr_any, 0));
    Lwt.catch
      (fun () ->
        (* Lwt on Win32 doesn't support Lwt_bytes.sendto *)
        let payload = Cstruct.to_string buf in
        Lwt_unix.sendto fd payload 0 (String.length payload) [] remote_sockaddr
        >>= fun n ->
        if n <> buf.Cstruct.len
        then Log.err (fun f -> f "DNS forwarder: Lwt_bytes.send short: expected %d got %d"  buf.Cstruct.len n);
        Lwt.return ()
      ) (fun e ->
        Log.err (fun f -> f "sendto failed with %s" (Printexc.to_string e));
        Lwt.return ()
      )
    >>= fun () ->
    let receiver =
      let bytes = Bytes.make 4096 '\000' in
      Lwt.catch
        (fun () ->
           (* Lwt on Win32 doesn't support Lwt_bytes.recvfrom *)
           Lwt_unix.recvfrom fd bytes 0 (String.length bytes) []
           >>= fun (n, _) ->
           let buffer = Cstruct.create n in
           Cstruct.blit_from_string bytes 0 buffer 0 n;
           Lwt.return (`Result buffer)
        ) (fun e ->
           Log.err (fun f -> f "recvfrom failed with %s" (Printexc.to_string e));
           Lwt.return `Error
        ) in
    let timeout = Lwt_unix.sleep 5. >>= fun () -> Lwt.return `Timeout in
    Lwt.pick [ receiver; timeout ]
    >>= fun r ->
    Lwt_unix.close fd
    >>= fun () ->
    match r with
    | `Error ->
      Lwt.return_unit
    | `Timeout ->
      Log.err (fun f -> f "DNS response timed out after 5s");
      Lwt.return_unit
    | `Result buffer ->
      Log.debug (fun f -> f "DNS %s:%d <- %s %s" src_str src_port dst_str (string_of_dns buffer));
      Tcpip_stack.UDPV4.write ~source_port:53 ~dest_ip:src ~dest_port:src_port (Tcpip_stack.udpv4 s) buffer
    end
  | _ ->
    Log.err (fun f -> f "No upstream DNS server configured: dropping request");
    Lwt.return_unit
  end else Lwt.return_unit
end

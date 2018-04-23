open Lwt.Infix

let src =
  let src = Logs.Src.create "Uwt" ~doc:"UDP NAT implementation" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

type reply = Cstruct.t -> unit Lwt.t

type address = Ipaddr.t * int

type datagram = {
  src: address;
  dst: address;
  intercept: address;
  payload: Cstruct.t;
}

(* A table mapping host ports to the corresponding internal address.
   This is needed for the ICMP implementation to send back TTL exceeded
   messages for UDP frames. The fact this is outside the functors suggests
   that the code is badly factored. *)
let external_to_internal = Hashtbl.create 7

module Make
    (Sockets: Sig.SOCKETS)
    (Clock: Mirage_clock_lwt.MCLOCK)
    (Time: Mirage_time_lwt.S) =
struct

  module Udp = Sockets.Datagram.Udp

  (* For every source address, we allocate a flow with a receiving loop *)
  type flow = {
    description: string;
    server: Udp.server;
    external_address: address;
    mutable last_use: int64;
  }

  (* For every src, src_port behind the NAT we create one listening socket
     on the external network. We translate the source address on the way out
     but preserve them on the way in. *)

  type t = {
    clock: Clock.t;
    max_idle_time: int64;
    background_gc_t: unit Lwt.t;
    table: (address, flow) Hashtbl.t; (* src -> flow *)
    mutable send_reply: (datagram -> unit Lwt.t) option;
    preserve_remote_port: bool;
  }

  let set_send_reply ~t ~send_reply = t.send_reply <- Some send_reply

  let get_nat_table_size t = Hashtbl.length t.table

  let start_background_gc clock table max_idle_time =
    let rec loop () =
      Time.sleep_ns max_idle_time >>= fun () ->
      let now_ns = Clock.elapsed_ns clock in
      let to_shutdown =
        Hashtbl.fold (fun k flow acc ->
            if Int64.(sub now_ns flow.last_use) > max_idle_time then begin
              Log.debug (fun f ->
                  f "Hostnet_udp %s: expiring UDP NAT rule" flow.description);
              (k, flow) :: acc
            end else acc
          ) table []
      in
      Lwt_list.iter_s (fun (k, flow) ->
          Lwt.catch (fun () ->
              Udp.shutdown flow.server
            ) (fun e ->
              Log.err (fun f ->
                  f "Hostnet_udp %s: close raised %a" flow.description Fmt.exn e);
              Lwt.return_unit
            )
          >>= fun () ->
          Hashtbl.remove table k;
          Hashtbl.remove external_to_internal (snd flow.external_address);
          Lwt.return_unit
        ) to_shutdown
      >>= fun () ->
      loop ()
    in
    loop ()

  let create ?(max_idle_time = Duration.(of_sec 60)) ?(preserve_remote_port=true) clock =
    let table = Hashtbl.create 7 in
    let background_gc_t = start_background_gc clock table max_idle_time in
    let send_reply = None in
    { clock; max_idle_time; background_gc_t; table; send_reply; preserve_remote_port }

  let description { src = src, src_port; dst = dst, dst_port; _ } =
    Fmt.strf "udp:%a:%d-%a:%d" Ipaddr.pp_hum src src_port Ipaddr.pp_hum
      dst dst_port

  let rec loop t server d buf =
    Lwt.catch (fun () ->
        Udp.recvfrom server buf
        >>= fun (n, from) ->
        (* In the default configuration with preserve_remote_port=true,
           the from address should be the true external address so the
           client behind the NAT can tell different peers apart.  It
           is not necessarily the same as the original external
           address that we created the rule for -- it's possible for a
           client to send data to a rendezvous server, which then
           communicates the NAT IP and port to other peers who can
           then communicate with the client behind the NAT.

           If preserve_remote_port=false then we reply with the original
           port number, as if we were a UDP proxy. Note the IP address is
           set by the `send_reply` function. *)
        let reply = { d with
          src = if t.preserve_remote_port then from else d.dst;
          dst = d.src;
          payload = Cstruct.sub buf 0 n
        } in
        ( match t.send_reply with
        | Some fn -> fn reply
        | None -> Lwt.return_unit )
        >>= fun () ->
        Lwt.return true
      ) (function
      | Unix.Unix_error(e, _, _) when
          Uwt.of_unix_error e = Uwt.ECANCELED ->
        Log.debug (fun f ->
            f "Hostnet_udp %s: shutting down listening thread" (description d));
        Lwt.return false
      | e ->
        Log.err (fun f ->
            f "Hostnet_udp %s: caught unexpected exception %a"
              (description d) Fmt.exn e);
        Lwt.return false
      )
    >>= function
    | false ->
      Lwt.return ()
    | true -> loop t server d buf

  let input ~t ~datagram ~ttl () =
    let d = description datagram in
    (if Hashtbl.mem t.table datagram.src then begin
        Lwt.return (Some (Hashtbl.find t.table datagram.src))
      end else begin
       if Ipaddr.compare (fst datagram.dst) Ipaddr.(V4 V4.broadcast) = 0
       then begin
         Log.debug (fun f -> f "Hostnet_udp %s: ignoring broadcast packet" d);
         Lwt.return None
       end else begin
         Log.debug (fun f -> f "Hostnet_udp %s: creating UDP NAT rule" d);
         Lwt.catch (fun () ->
             Udp.bind ~description:(description datagram) (Ipaddr.(V4 V4.any), 0)
             >>= fun server ->
             let external_address = Udp.getsockname server in
             let last_use = Clock.elapsed_ns t.clock in
             let flow = { description = d; server; external_address; last_use } in
             Hashtbl.replace t.table datagram.src flow;
             Hashtbl.replace external_to_internal (snd external_address) datagram.src;
             (* Start a listener *)
             let buf = Cstruct.create Constants.max_udp_length in
             Lwt.async (fun () -> loop t server datagram buf);
             Lwt.return (Some flow)
           ) (fun e ->
             Log.err (fun f -> f "Hostnet_udp.input: bind raised %a" Fmt.exn e);
             Lwt.return None
           )
       end
     end) >>= function
    | None -> Lwt.return ()
    | Some flow ->
      Lwt.catch (fun () ->
          Udp.sendto flow.server datagram.intercept ~ttl datagram.payload >|= fun () ->
          flow.last_use <- Clock.elapsed_ns t.clock;
        ) (fun e ->
          Log.err (fun f ->
              f "Hostnet_udp %s: Lwt_bytes.send caught %a"
                flow.description Fmt.exn e);
          Lwt.return ()
        )
end

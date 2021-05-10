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
    src: address;
    server: Udp.server;
    external_address: address;
    mutable last_use: int64;
  }

  (* We keep a map of last_use (nanosecond) -> flow so we can partition it
     and expire the oldest. *)
  module By_last_use = Map.Make(Int64)

  (* For every src, src_port behind the NAT we create one listening socket
     on the external network. We translate the source address on the way out
     but preserve them on the way in. *)

  type t = {
    clock: Clock.t;
    max_idle_time: int64;
    max_active_flows: int;
    new_flow_lock: Lwt_mutex.t;
    background_gc_t: unit Lwt.t;
    table: (address, flow) Hashtbl.t; (* src -> flow *)
    by_last_use: flow By_last_use.t ref; (* last use -> flow *)
    mutable send_reply: (datagram -> unit Lwt.t) option;
    preserve_remote_port: bool;
  }

  let set_send_reply ~t ~send_reply = t.send_reply <- Some send_reply

  module Debug = struct
    type address = Ipaddr.t * int

    type flow = {
      inside: address;
      outside: address;
      last_use_time_ns: int64;
    }

    let get_table t =
      Hashtbl.fold (fun _ flow acc ->
        {
          inside = flow.src;
          outside = flow.external_address;
          last_use_time_ns = flow.last_use;
        } :: acc
      ) t.table []

    let get_max_active_flows t = t.max_active_flows
  end

  let expire table by_last_use flow =
    Lwt.catch (fun () ->
        Udp.shutdown flow.server
      ) (fun e ->
        Log.err (fun f ->
            f "Hostnet_udp %s: close raised %a" flow.description Fmt.exn e);
        Lwt.return_unit
      )
    >>= fun () ->
    Hashtbl.remove table flow.src;
    Hashtbl.remove external_to_internal (snd flow.external_address);
    by_last_use := By_last_use.remove flow.last_use (!by_last_use);
    Lwt.return_unit

  let touch t flow =
    let last_use = Clock.elapsed_ns t.clock in
    (* Remove the old entry t.last_use and add a new one for last_use *)
    t.by_last_use := By_last_use.(add last_use flow @@ remove flow.last_use !(t.by_last_use));
    flow.last_use <- last_use

  let start_background_gc clock table by_last_use max_idle_time new_flow_lock =
    let rec loop () =
      Time.sleep_ns max_idle_time >>= fun () ->
      Lwt_mutex.with_lock new_flow_lock
        (fun () ->
          let now_ns = Clock.elapsed_ns clock in
          let to_shutdown =
            Hashtbl.fold (fun _ flow acc ->
                if Int64.(sub now_ns flow.last_use) > max_idle_time then begin
                  Log.debug (fun f ->
                      f "Hostnet_udp %s: expiring UDP NAT rule" flow.description);
                  flow :: acc
                end else acc
              ) table []
          in
          Lwt_list.iter_s (expire table by_last_use) to_shutdown
        )
      >>= fun () ->
      loop ()
    in
    loop ()

  let create ?(max_idle_time = Duration.(of_sec 60)) ?(preserve_remote_port=true) ?(max_active_flows=1024) clock =
    let table = Hashtbl.create 7 in
    let by_last_use = ref By_last_use.empty in
    let new_flow_lock = Lwt_mutex.create () in
    let background_gc_t = start_background_gc clock table by_last_use max_idle_time new_flow_lock in
    let send_reply = None in
    { clock; max_idle_time; max_active_flows; new_flow_lock; background_gc_t; table; by_last_use; send_reply; preserve_remote_port }

  let description { src = src, src_port; dst = dst, dst_port; _ } =
    Fmt.strf "udp:%a:%d-%a:%d" Ipaddr.pp src src_port Ipaddr.pp
      dst dst_port

  let outside_to_inside t flow server d =
    let buf = Cstruct.create Constants.max_udp_length in
    let rec loop () =
      Lwt.catch (fun () ->
        Udp.recvfrom server buf
        >>= fun (n, from) ->
        touch t flow;
        (* Copy the payload because lower down in the stack we will keep
           references, for example in the .pcap capturing logic. *)
        let payload = Cstruct.create n in
        Cstruct.blit buf 0 payload 0 n;
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
          payload;
        } in
        ( match t.send_reply with
        | Some fn -> fn reply
        | None -> Lwt.return_unit )
        >>= fun () ->
        Lwt.return true
      ) (function
      | e ->
        Log.err (fun f ->
            f "Hostnet_udp %s: caught unexpected exception %a"
              (description d) Fmt.exn e);
        Lwt.return false
      )
      >>= function
      | false ->
        Lwt.return ()
      | true -> loop () in
    loop ()

  let expire_old_flows_locked t =
    let current = By_last_use.cardinal !(t.by_last_use) in
    if current < t.max_active_flows
    then Lwt.return_unit
    else begin
      (* Although we want a hard limit of max_active_flows, when we hit the
          limit we will expire the oldest 25% to amortise the cost. *)
      let to_delete = current - (t.max_active_flows / 4 * 3) in
      let seq = By_last_use.to_seq !(t.by_last_use) in
      let rec loop remaining seq count = match remaining, seq () with
        | _, Seq.Nil -> Lwt.return count
        | 0, _ -> Lwt.return count
        | n, Cons((_, oldest_flow), rest) ->
          expire t.table t.by_last_use oldest_flow
          >>= fun () ->
          loop (n - 1) rest (count + 1) in
      loop to_delete seq 0
      >>= fun count ->
      Log.info (fun f -> f "Expired %d UDP NAT rules" count);
      Lwt.return_unit
    end

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
            Lwt_mutex.with_lock t.new_flow_lock
              (fun () ->
                (* Re-check the table with the lock held as another thread might
                   have acquired the lock before us. *)
                if Hashtbl.mem t.table datagram.src
                then Lwt.return (Some (Hashtbl.find t.table datagram.src))
                else begin
                  expire_old_flows_locked t
                  >>= fun () ->
                  Udp.bind ~description:(description datagram) (Ipaddr.(V4 V4.any), 0)
                  >>= fun server ->
                  Udp.getsockname server
                  >>= fun external_address ->
                  let last_use = Clock.elapsed_ns t.clock in
                  let flow = { description = d; src = datagram.src; server; external_address; last_use } in
                  Hashtbl.replace t.table datagram.src flow;
                  t.by_last_use := By_last_use.add last_use flow !(t.by_last_use);
                  Hashtbl.replace external_to_internal (snd external_address) datagram.src;
                  (* Start a listener *)
                  Lwt.async (fun () -> outside_to_inside t flow server datagram);
                  Lwt.return (Some flow)
                end
              )
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
          touch t flow
        ) (fun e ->
          Log.err (fun f ->
              f "Hostnet_udp %s: Lwt_bytes.send caught %a"
                flow.description Fmt.exn e);
          Lwt.return ()
        )
end

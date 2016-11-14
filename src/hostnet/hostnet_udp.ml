
open Lwt.Infix

let src =
  let src = Logs.Src.create "Uwt" ~doc:"UDP NAT implementation" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

type reply = Cstruct.t -> unit Lwt.t

type address = Ipaddr.t * int

module Make(Sockets: Sig.SOCKETS)(Time: V1_LWT.TIME) = struct

  module Udp = Sockets.Datagram.Udp

  type t = {
    max_idle_time: float;
    background_gc_t: unit Lwt.t;
  }

  type flow = {
    description: string;
    server: Udp.server;
    mutable last_use: float;
    (* For protocols like NTP the source port keeps changing, so we send
       replies to the last source port we saw. *)
    mutable reply: reply;
  }

  (* Look up by src * src_port *)
  let table = Hashtbl.create 7

  let get_nat_table_size () = Hashtbl.length table

  let start_background_gc max_idle_time =
    let rec loop () =
      Time.sleep max_idle_time
      >>= fun () ->
      let now = Unix.gettimeofday () in
      let to_shutdown = Hashtbl.fold (fun k flow acc ->
          if now -. flow.last_use > max_idle_time then begin
            Log.debug (fun f -> f "Hostnet_udp %s: expiring UDP NAT rule" flow.description);
            (k, flow) :: acc
          end else acc
        ) table [] in
      Lwt_list.iter_s
        (fun (k, flow) ->
           Lwt.catch
             (fun () ->
                Udp.shutdown flow.server
             ) (fun e ->
                 Log.err (fun f -> f "Hostnet_udp %s: close raised %s" flow.description (Printexc.to_string e));
                 Lwt.return_unit
               )
           >>= fun () ->
           Hashtbl.remove table k;
           Lwt.return_unit
        ) to_shutdown
      >>= fun () ->
      loop () in
    loop ()

  let create ?(max_idle_time = 60.) () =
    let background_gc_t = start_background_gc max_idle_time in
    { max_idle_time; background_gc_t }

  let input ~t:_ ?userdesc ~oneshot ~reply ~src:(src, src_port) ~dst:(dst, dst_port) ~payload () =
    (if Hashtbl.mem table (src, src_port) then begin
        Lwt.return (Some (Hashtbl.find table (src, src_port)))
      end else begin
       let userdesc = match userdesc with
         | None -> ""
         | Some x -> String.concat "" [ " ("; x; ")" ] in
       let description = "udp:" ^ (String.concat "" [ Ipaddr.to_string src; ":"; string_of_int src_port; "-"; Ipaddr.to_string dst; ":"; string_of_int dst_port; userdesc ]) in
       if Ipaddr.compare dst Ipaddr.(V4 V4.broadcast) = 0 then begin
         Log.debug (fun f -> f "Hostnet_udp %s: ignoring broadcast packet" description);
         Lwt.return None
       end else begin
         Log.debug (fun f -> f "Hostnet_udp %s: creating UDP NAT rule" description);

         Lwt.catch
           (fun () ->
              Udp.bind (Ipaddr.(V4 V4.any), 0)
              >>= fun server ->
              let last_use = Unix.gettimeofday () in
              let flow = { description; server; last_use; reply} in
              Hashtbl.replace table (src, src_port) flow;
              (* Start a listener *)
              let buf = Cstruct.create Constants.max_udp_length in
              let rec loop () =
                Lwt.catch
                  (fun () ->
                     Udp.recvfrom server buf
                     >>= fun (n, _from) ->
                     ( if oneshot then begin
                           (* Remove our flow entry immediately, clean up synchronously *)
                           Log.debug (fun f -> f "Hostnet_udp %s: expiring UDP NAT rule immediately" flow.description);
                           Hashtbl.remove table (src, src_port);
                           Udp.shutdown server
                         end else Lwt.return_unit )
                     >>= fun () ->
                     flow.reply (Cstruct.sub buf 0 n)
                     >>= fun () ->
                     Lwt.return (not oneshot)
                  ) (function
                      | Uwt.Uwt_error(Uwt.ECANCELED, _, _) ->
                        (* fd has been closed by the GC *)
                        Log.debug (fun f -> f "Hostnet_udp %s: shutting down listening thread" description);
                        Lwt.return false
                      | e ->
                        Log.err (fun f -> f "Hostnet_udp %s: caught unexpected exception %s" description (Printexc.to_string e));
                        Lwt.return false
                    )
                >>= function
                | false ->
                  Lwt.return ()
                | true -> loop () in
              Lwt.async loop;
              Lwt.return (Some flow)
           ) (fun e ->
               Log.err (fun f -> f "Hostnet_udp.input: bind raised %s" (Printexc.to_string e));
               Lwt.return None
             )
       end
     end) >>= function
    | None -> Lwt.return ()
    | Some flow ->
      flow.reply <- reply;
      Lwt.catch
        (fun () ->
           Udp.sendto flow.server (dst, dst_port) payload
           >>= fun () ->
           flow.last_use <- Unix.gettimeofday ();
           Lwt.return ()
        ) (fun e ->
            Log.err (fun f -> f "Hostnet_udp %s: Lwt_bytes.send caught %s" flow.description (Printexc.to_string e));
            Lwt.return ()
          )
end

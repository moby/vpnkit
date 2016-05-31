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

let parse_dns buf =
  let len = Cstruct.len buf in
  let buf = Dns.Buf.of_cstruct buf in
  (len, Dns.Protocol.Server.parse (Dns.Buf.sub buf 0 len))

let string_of_dns dns =
  match dns with
  | (len, None) ->
    Printf.sprintf "Unparsable DNS packet length %d" len
  | (_, Some request) ->
    Dns.Packet.to_string request

let tidstr_of_dns dns =
  match dns with
  | (_, None) -> "----"
  | (_, Some { Dns.Packet.id }) -> Printf.sprintf "%04x" id

module Make(Ip: V1_LWT.IPV4) (Udp:V1_LWT.UDPV4) (Resolv_conf: Sig.RESOLV_CONF) = struct

type transaction = {
  mutable resolvers : (Ipaddr.t * int) list;
  mutable used_resolvers : (Ipaddr.t * int) list;
  mutable last_use: float;
}

let table = Hashtbl.create 7

let start_reaper () =
  let rec loop () =
    let open Lwt.Infix in
    Lwt_unix.sleep 60.
    >>= fun () ->
    let snapshot = Hashtbl.copy table in
    let now = Unix.gettimeofday () in
    Hashtbl.iter (fun k trec ->
      if now -. trec.last_use > 60. then begin
        Log.debug (fun f -> f "DNS[%04x] Expiring DNS trec" k);
        Hashtbl.remove table k
      end
    ) snapshot;
    loop () in
  loop ()

let input ~ip ~udp ~src ~dst ~src_port buf =
  if List.mem dst (Ip.get_ip ip) then begin

  let src_str = Ipaddr.V4.to_string src in
  let dst_str = Ipaddr.V4.to_string dst in

  let dns = parse_dns buf in

  let remove_tid dns =
    match dns with
    | (_, None) -> ()
    | (_, Some { Dns.Packet.id }) -> Hashtbl.remove table id in

  Log.debug (fun f -> f "DNS[%s] %s:%d -> %s %s" (tidstr_of_dns dns) src_str src_port dst_str (string_of_dns dns));

  match dns with
  | (_, None) -> begin
    Resolv_conf.get ()
    >>= function
    | r::_ -> Lwt.return_some r
    | _ -> Lwt.return_none
  end
  | (_, Some { Dns.Packet.id = tid }) -> begin
    Lwt.catch
      (fun () ->
        let trec = Hashtbl.find table tid in
        let r, rs, urs = match trec.resolvers with
          | r::rs -> (r,rs,r::trec.used_resolvers)
          | _ -> match List.rev trec.used_resolvers with
            | r::rs -> (r,rs,[])
            | _  -> assert false (* resolvers and used_resolvers cannot both be empty *)
        in
        Log.debug (fun f -> f "DNS[%s] Retry" (tidstr_of_dns dns));
        trec.resolvers <- rs;
        trec.used_resolvers <- urs;
        trec.last_use <- Unix.gettimeofday ();
        Lwt.return_some r
      )
      (function
      | Not_found -> begin
         (* Re-read /etc/resolv.conf on every request. This ensures that
            changes to DNS on sleep/resume or switching networks are reflected
            immediately. The file is very small, and parsing it shouldn't be
            too slow. *)
        Resolv_conf.get ()
        >>= function
        | r::rs -> begin
          let last_use = Unix.gettimeofday () in
          let trec = { resolvers = rs; used_resolvers = r :: []; last_use } in
          Hashtbl.replace table tid trec;
          Lwt.return_some r
        end
        | _ -> Lwt.return_none
      end
      | ex -> Lwt.fail ex
      )
  end;
  >>= function
  | Some (dst, dst_port) -> begin
    let remote_sockaddr = Lwt_unix.ADDR_INET(Unix.inet_addr_of_string @@ Ipaddr.to_string dst, dst_port) in

    let fd = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_DGRAM 0 in
    Log.debug (fun f -> f "DNS[%s] Forwarding to %s" (tidstr_of_dns dns) (Ipaddr.to_string dst));
    Lwt_unix.connect fd remote_sockaddr;
    Lwt.catch
      (fun () ->
        let payload = Cstruct.to_string buf in
        Lwt_unix.send fd payload 0 (String.length payload) []
        >>= fun n ->
        if n <> buf.Cstruct.len
        then Log.err (fun f -> f "DNS[%s] forwarder: Lwt_bytes.send short: expected %d got %d" (tidstr_of_dns dns) buf.Cstruct.len n);
        Lwt.return ()
      ) (fun e ->
        Log.err (fun f -> f "DNS[%s] send failed with %s" (tidstr_of_dns dns) (Printexc.to_string e));
        Lwt.return ()
      )
    >>= fun () ->
    let receiver =
      let bytes = Bytes.make 4096 '\000' in
      Lwt.catch
        (fun () ->
          Lwt_unix.recv fd bytes 0 (String.length bytes) []
           >>= fun n ->
           let buffer = Cstruct.create n in
           Cstruct.blit_from_string bytes 0 buffer 0 n;
           Lwt.return (`Result buffer)
        ) (fun e ->
           Log.err (fun f -> f "DNS[%s] recv failed with %s" (tidstr_of_dns dns) (Printexc.to_string e));
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
      Log.err (fun f -> f "DNS[%s] timed out after 5s" (tidstr_of_dns dns));
      Lwt.return_unit
    | `Result buffer ->
      Log.debug (fun f -> f "DNS[%s] %s:%d <- %s %s" (tidstr_of_dns dns) src_str src_port dst_str (string_of_dns (parse_dns buffer)));
      remove_tid dns;
      Udp.write ~source_port:53 ~dest_ip:src ~dest_port:src_port udp buffer
    end
  | None ->
    Log.err (fun f -> f "DNS[%s] No upstream DNS server configured: dropping request" (tidstr_of_dns dns));
    Lwt.return_unit
  end else Lwt.return_unit
end

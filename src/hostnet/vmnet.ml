open Lwt.Infix

let src =
  let src = Logs.Src.create "vmnet" ~doc:"vmnet" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let ethernet_header_length = 14 (* no VLAN *)

module Init = struct

  type t = {
    magic: string;
    version: int32;
    commit: string;
  }

  let to_string t =
    Fmt.strf "{ magic = %s; version = %ld; commit = %s }"
      t.magic t.version t.commit

  let sizeof = 5 + 4 + 40

  let default = {
    magic = "VMN3T";
    version = 22l;
    commit = "0123456789012345678901234567890123456789";
  }

  let marshal t rest =
    Cstruct.blit_from_string t.magic 0 rest 0 5;
    Cstruct.LE.set_uint32 rest 5 t.version;
    Cstruct.blit_from_string t.commit 0 rest 9 40;
    Cstruct.shift rest sizeof

  let unmarshal rest =
    let magic = Cstruct.(to_string @@ sub rest 0 5) in
    let version = Cstruct.LE.get_uint32 rest 5 in
    let commit = Cstruct.(to_string @@ sub rest 9 40) in
    let rest = Cstruct.shift rest sizeof in
    { magic; version; commit }, rest
end

module Command = struct

  type t =
    | Ethernet of Uuidm.t (* 36 bytes *)
    | Preferred_ipv4 of Uuidm.t (* 36 bytes *) * Ipaddr.V4.t
    | Bind_ipv4 of Ipaddr.V4.t * int * bool

  let to_string = function
  | Ethernet x -> Fmt.strf "Ethernet %a" Uuidm.pp x
  | Preferred_ipv4 (uuid, ip) ->
    Fmt.strf "Preferred_ipv4 %a %a" Uuidm.pp uuid Ipaddr.V4.pp ip
  | Bind_ipv4 (ip, port, tcp) ->
    Fmt.strf "Bind_ipv4 %a %d %b" Ipaddr.V4.pp ip port tcp

  let sizeof = 1 + 36 + 4

  let marshal t rest = match t with
  | Ethernet uuid ->
    Cstruct.set_uint8 rest 0 1;
    let rest = Cstruct.shift rest 1 in
    let uuid_str = Uuidm.to_string uuid in
    Cstruct.blit_from_string uuid_str 0 rest 0 (String.length uuid_str);
    Cstruct.shift rest (String.length uuid_str)
  | Preferred_ipv4 (uuid, ip) ->
    Cstruct.set_uint8 rest 0 8;
    let rest = Cstruct.shift rest 1 in
    let uuid_str = Uuidm.to_string uuid in
    Cstruct.blit_from_string uuid_str 0 rest 0 (String.length uuid_str);
    let rest = Cstruct.shift rest (String.length uuid_str) in
    Cstruct.LE.set_uint32 rest 0 (Ipaddr.V4.to_int32 ip);
    Cstruct.shift rest 4
  | Bind_ipv4 (ip, port, stream) ->
    Cstruct.set_uint8 rest 0 6;
    let rest = Cstruct.shift rest 1 in
    Cstruct.LE.set_uint32 rest 0 (Ipaddr.V4.to_int32 ip);
    let rest = Cstruct.shift rest 4 in
    Cstruct.LE.set_uint16 rest 0 port;
    let rest = Cstruct.shift rest 2 in
    Cstruct.set_uint8 rest 0 (if stream then 0 else 1);
    Cstruct.shift rest 1

  let unmarshal rest =
    let process_uuid uuid_str =
      if (String.compare (String.make 36 '\000') uuid_str) = 0 then
        begin
          let random_uuid = (Uuidm.v `V4) in
          Log.info (fun f ->
              f "Generated UUID on behalf of client: %a" Uuidm.pp random_uuid);
          (* generate random uuid on behalf of client if client sent
             array of \0 *)
          Some random_uuid
        end else
          Uuidm.of_string uuid_str
    in
    match Cstruct.get_uint8 rest 0 with
    | 1 -> (* ethernet *)
      let uuid_str = Cstruct.(to_string (sub rest 1 36)) in
      let rest = Cstruct.shift rest 37 in
      (match process_uuid uuid_str with
       | Some uuid -> Ok (Ethernet uuid, rest)
       | None -> Error (`Msg (Printf.sprintf "Invalid UUID: %s" uuid_str)))
    | 8 -> (* preferred_ipv4 *)
      let uuid_str = Cstruct.(to_string (sub rest 1 36)) in
      let rest = Cstruct.shift rest 37 in
      let ip = Ipaddr.V4.of_int32 (Cstruct.LE.get_uint32 rest 0) in
      let rest = Cstruct.shift rest 4 in
      (match process_uuid uuid_str with
      | Some uuid -> Ok (Preferred_ipv4 (uuid, ip), rest)
      | None -> Error (`Msg (Printf.sprintf "Invalid UUID: %s" uuid_str)))
    | n -> Error (`Msg (Printf.sprintf "Unknown command: %d" n))

end

module Vif = struct

  type t = {
    mtu: int;
    max_packet_size: int;
    client_macaddr: Macaddr.t;
  }

  let to_string t =
    Fmt.strf "{ mtu = %d; max_packet_size = %d; client_macaddr = %s }"
      t.mtu t.max_packet_size (Macaddr.to_string t.client_macaddr)

  let create client_macaddr mtu () =
    let max_packet_size = mtu + 50 in
    { mtu; max_packet_size; client_macaddr }

  let sizeof = 2 + 2 + 6

  let marshal t rest =
    Cstruct.LE.set_uint16 rest 0 t.mtu;
    Cstruct.LE.set_uint16 rest 2 t.max_packet_size;
    Cstruct.blit_from_string (Macaddr.to_bytes t.client_macaddr) 0 rest 4 6;
    Cstruct.shift rest sizeof

  let unmarshal rest =
    let mtu = Cstruct.LE.get_uint16 rest 0 in
    let max_packet_size = Cstruct.LE.get_uint16 rest 2 in
    let mac = Cstruct.(to_string @@ sub rest 4 6) in
    try
      let client_macaddr = Macaddr.of_bytes_exn mac in
      Ok ({ mtu; max_packet_size; client_macaddr }, Cstruct.shift rest sizeof)
    with _ ->
      Error (`Msg (Printf.sprintf "Failed to parse MAC: [%s]" mac))

end

module Response = struct
  type t =
    | Vif of Vif.t (* 10 bytes *)
    | Disconnect of string (* disconnect reason *)

  let sizeof = 1+1+256 (* leave room for error message and length *)

  let marshal t rest = match t with
  | Vif vif ->
    Cstruct.set_uint8 rest 0 1;
    let rest = Cstruct.shift rest 1 in
    Vif.marshal vif rest
  | Disconnect reason ->
    Cstruct.set_uint8 rest 0 2;
    let rest = Cstruct.shift rest 1 in
    Cstruct.set_uint8 rest 0 (String.length reason);
    let rest = Cstruct.shift rest 1 in
    Cstruct.blit_from_string reason 0 rest 0 (String.length reason);
    Cstruct.shift rest (String.length reason)

  let unmarshal rest =
    match Cstruct.get_uint8 rest 0 with
    | 1 -> (* vif *)
      let rest = Cstruct.shift rest 1 in
      let vif = Vif.unmarshal rest in
      (match vif with
      | Ok (vif, rest) -> Ok (Vif vif, rest)
      | Error msg -> Error (msg))
    | 2 -> (* disconnect *)
      let rest = Cstruct.shift rest 1 in
      let str_len = Cstruct.get_uint8 rest 0 in
      let rest = Cstruct.shift rest 1 in
      let reason_str = Cstruct.(to_string (sub rest 0 str_len)) in
      let rest = Cstruct.shift rest str_len in
      Ok (Disconnect reason_str, rest)
    | n -> Error (`Msg (Printf.sprintf "Unknown response: %d" n))

end


module Packet = struct
  let sizeof = 2

  let marshal t rest =
    Cstruct.LE.set_uint16 rest 0 t

  let unmarshal rest =
    let t = Cstruct.LE.get_uint16 rest 0 in
    Ok (t, Cstruct.shift rest sizeof)
end

module Make(C: Sig.CONN) = struct

  module Channel = Mirage_channel_lwt.Make(C)

  type page_aligned_buffer = Io_page.t
  type macaddr = Macaddr.t
  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type error = [Mirage_device.error | `Channel of Channel.write_error]

  let pp_error ppf = function
  | #Mirage_device.error as e -> Mirage_device.pp_error ppf e
  | `Channel e                -> Channel.pp_write_error ppf e

  let failf fmt = Fmt.kstrf (fun e -> Lwt_result.fail (`Msg e)) fmt

  type t = {
    mutable fd: Channel.t option;
    stats: Mirage_net.stats;
    client_uuid: Uuidm.t;
    client_macaddr: Macaddr.t;
    server_macaddr: Macaddr.t;
    mtu: int;
    mutable write_header: Cstruct.t;
    write_m: Lwt_mutex.t;
    mutable pcap: Unix.file_descr option;
    mutable pcap_size_limit: int64 option;
    pcap_m: Lwt_mutex.t;
    mutable listeners: (Cstruct.t -> unit Lwt.t) list;
    mutable listening: bool;
    after_disconnect: unit Lwt.t;
    after_disconnect_u: unit Lwt.u;
    (* NB: The Mirage DHCP client calls `listen` and then later the
       Tcp_direct_direct will do the same. This behaviour seems to be
       undefined, but common implementations adopt a last-caller-wins
       semantic. This is the last caller wins callback *)
    mutable callback: (Cstruct.t -> unit io);
    log_prefix: string;
  }

  let get_client_uuid t =
    t.client_uuid

  let get_client_macaddr t =
    t.client_macaddr

  let err_eof = Lwt_result.fail (`Msg "EOF")
  let err_read e = failf "while reading: %a" Channel.pp_error e
  let err_flush e = failf "while flushing: %a" Channel.pp_write_error e

  let with_read x f =
    x >>= function
    | Error e      -> err_read e
    | Ok `Eof      -> err_eof
    | Ok (`Data x) -> f x

  let with_flush x f =
    x >>= function
    | Error e -> err_flush e
    | Ok ()   -> f ()

  let with_msg x f =
    match x with
    | Ok x -> f x
    | Error _ as e -> Lwt.return e

  let server_log_prefix = "Vmnet.Server"
  let client_log_prefix = "Vmnet.Client"

  let server_negotiate ~fd ~connect_client_fn ~mtu =
    let assign_uuid_ip uuid ip =
      connect_client_fn uuid ip >>= fun mac ->
      match mac with
      | Error (`Msg msg) ->
          let buf = Cstruct.create Response.sizeof in
          let (_: Cstruct.t) = Response.marshal (Disconnect msg) buf in
          Log.err (fun f -> f "%s.negotiate: disconnecting client, reason: %s" server_log_prefix msg);
          Channel.write_buffer fd buf;
          with_flush (Channel.flush fd) @@ fun () ->
          failf "%s.negotiate: disconnecting client, reason: %s " server_log_prefix msg
      | Ok client_macaddr -> 
          let vif = Vif.create client_macaddr mtu () in
          let buf = Cstruct.create Response.sizeof in
          let (_: Cstruct.t) = Response.marshal (Vif vif) buf in
          Log.info (fun f -> f "%s.negotiate: sending %s" server_log_prefix (Vif.to_string vif));
          Channel.write_buffer fd buf;
          with_flush (Channel.flush fd) @@ fun () ->
          Lwt_result.return (uuid, client_macaddr)
    in
    with_read (Channel.read_exactly ~len:Init.sizeof fd) @@ fun bufs ->
    let buf = Cstruct.concat bufs in
    let init, _ = Init.unmarshal buf in
    Log.info (fun f -> f "%s.negotiate: received %s" server_log_prefix (Init.to_string init));
    match init.version with
    | 22l -> begin
        let (_: Cstruct.t) = Init.marshal Init.default buf in
        Channel.write_buffer fd buf;
        with_flush (Channel.flush fd) @@ fun () ->
        with_read (Channel.read_exactly ~len:Command.sizeof fd) @@ fun bufs ->
        let buf = Cstruct.concat bufs in
        with_msg (Command.unmarshal buf) @@ fun (command, _) ->
        Log.info (fun f ->
            f "%s.negotiate: received %s" server_log_prefix (Command.to_string command));
        match command with
        | Command.Bind_ipv4 _ -> 
          let buf = Cstruct.create Response.sizeof in
          let (_: Cstruct.t) = Response.marshal (Disconnect "Unsupported command Bind_ipv4") buf in
          Channel.write_buffer fd buf;
          with_flush (Channel.flush fd) @@ fun () ->
          failf "%s.negotiate: unsupported command Bind_ipv4" server_log_prefix
        | Command.Ethernet uuid -> assign_uuid_ip uuid None
        | Command.Preferred_ipv4 (uuid, ip) -> assign_uuid_ip uuid (Some ip)
      end
    | x -> 
      let (_: Cstruct.t) = Init.marshal Init.default buf in (* write our version before disconnecting *)
      Channel.write_buffer fd buf;
      with_flush (Channel.flush fd) @@ fun () ->
      Log.err (fun f -> f "%s: Client requested protocol version %s, server only supports version %s" server_log_prefix (Int32.to_string x) (Int32.to_string Init.default.version));
      Lwt_result.fail (`Msg "Client requested unsupported protocol version")


  let client_negotiate ~uuid ?preferred_ip ~fd () =
    let buf = Cstruct.create Init.sizeof in
    let (_: Cstruct.t) = Init.marshal Init.default buf in
    Channel.write_buffer fd buf;
    with_flush (Channel.flush fd) @@ fun () ->
    with_read (Channel.read_exactly ~len:Init.sizeof fd) @@ fun bufs ->
    let buf = Cstruct.concat bufs in
    let init, _ = Init.unmarshal buf in
    Log.info (fun f -> f "%s.negotiate: received %s" client_log_prefix (Init.to_string init));
    match init.version with
    | 22l -> 
        let buf = Cstruct.create Command.sizeof in
        let (_: Cstruct.t) = match preferred_ip with
          | None -> Command.marshal (Command.Ethernet uuid) buf
          | Some ip -> Command.marshal (Command.Preferred_ipv4 (uuid, ip)) buf
        in
        Channel.write_buffer fd buf;
        with_flush (Channel.flush fd) @@ fun () ->
        with_read (Channel.read_exactly ~len:Response.sizeof fd) @@ fun bufs ->
        let buf = Cstruct.concat bufs in
        let open Lwt_result.Infix in
        Lwt.return (Response.unmarshal buf) >>= fun (response, _) ->
        (match response with
        | Vif vif -> 
          Log.debug (fun f -> f "%s.negotiate: vif %s" client_log_prefix (Vif.to_string vif));
          Lwt_result.return (vif)
        | Disconnect reason ->
          let msg = "Server disconnected with reason: " ^ reason in
          Log.err (fun f -> f "%s.negotiate: %s" client_log_prefix msg);
          Lwt_result.fail (`Msg msg))
    | x -> 
        Log.err (fun f -> f "%s: Server requires protocol version %s, we have %s" client_log_prefix (Int32.to_string x) (Int32.to_string Init.default.version));
        Lwt_result.fail (`Msg "Server does not support our version of the protocol")

  (* Use blocking I/O here so we can avoid Using Lwt_unix or Uwt. Ideally we
     would use a FLOW handle referencing a file/stream. *)
  let really_write fd str =
    let rec loop ofs =
      if ofs = (Bytes.length str)
      then ()
      else
        let n = Unix.write fd str ofs (Bytes.length str - ofs) in
        loop (ofs + n)
    in
    loop 0

  let start_capture t ?size_limit filename =
    Lwt_mutex.with_lock t.pcap_m (fun () ->
        (match t.pcap with Some fd -> Unix.close fd | None -> ());
        let fd =
          Unix.openfile filename [ Unix.O_WRONLY; Unix.O_TRUNC; Unix.O_CREAT ]
            0o0644
        in
        let buf = Cstruct.create Pcap.LE.sizeof_pcap_header in
        let open Pcap.LE in
        set_pcap_header_magic_number buf Pcap.magic_number;
        set_pcap_header_version_major buf Pcap.major_version;
        set_pcap_header_version_minor buf Pcap.minor_version;
        set_pcap_header_thiszone buf 0l;
        set_pcap_header_sigfigs buf 4l;
        set_pcap_header_snaplen buf 1500l;
        set_pcap_header_network buf
          (Pcap.Network.to_int32 Pcap.Network.Ethernet);
        really_write fd (Cstruct.to_string buf |> Bytes.of_string);
        t.pcap <- Some fd;
        t.pcap_size_limit <- size_limit;
        Lwt.return ()
      )

  let stop_capture_already_locked t = match t.pcap with
  | None    -> ()
  | Some fd ->
    Unix.close fd;
    t.pcap <- None;
    t.pcap_size_limit <- None

  let stop_capture t =
    Lwt_mutex.with_lock t.pcap_m  (fun () ->
        stop_capture_already_locked t;
        Lwt.return_unit
      )

  let make ~client_macaddr ~server_macaddr ~mtu ~client_uuid ~log_prefix fd =
    let fd = Some fd in
    let stats = Mirage_net.Stats.create () in
    let write_header = Cstruct.create (1024 * Packet.sizeof) in
    let write_m = Lwt_mutex.create () in
    let pcap = None in
    let pcap_size_limit = None in
    let pcap_m = Lwt_mutex.create () in
    let listeners = [] in
    let listening = false in
    let after_disconnect, after_disconnect_u = Lwt.task () in
    let callback _ = Lwt.return_unit in
    { fd; stats; client_macaddr; client_uuid; server_macaddr; mtu; write_header;
      write_m; pcap; pcap_size_limit; pcap_m; listeners; listening;
      after_disconnect; after_disconnect_u; callback; log_prefix }

  type fd = C.flow

  let of_fd ~connect_client_fn ~server_macaddr ~mtu flow =
    let open Lwt_result.Infix in
    let channel = Channel.create flow in
    server_negotiate ~fd:channel ~connect_client_fn ~mtu
    >>= fun (client_uuid, client_macaddr) ->
    let t = make ~client_macaddr ~server_macaddr ~mtu ~client_uuid
        ~log_prefix:server_log_prefix channel in
    Lwt_result.return t

  let client_of_fd ~uuid ?preferred_ip ~server_macaddr flow =
    let open Lwt_result.Infix in
    let channel = Channel.create flow in
    client_negotiate ~uuid ?preferred_ip ~fd:channel ()
    >>= fun vif ->
    let t =
      make ~client_macaddr:server_macaddr
        ~server_macaddr:vif.Vif.client_macaddr ~mtu:vif.Vif.mtu ~client_uuid:uuid
        ~log_prefix:client_log_prefix
        channel in
    Lwt_result.return t

  let disconnect t = match t.fd with
  | None    -> Lwt.return ()
  | Some fd ->
    Log.info (fun f -> f "%s.disconnect" t.log_prefix);
    t.fd <- None;
    Log.debug (fun f -> f "%s.disconnect flushing channel" t.log_prefix);
    (Channel.flush fd >|= function
      | Ok ()   -> ()
      | Error e ->
        Log.err (fun l ->
            l "%s error while disconnecting the vmtnet connection: %a"
              t.log_prefix Channel.pp_write_error e);
    ) >|= fun () ->
    Lwt.wakeup_later t.after_disconnect_u ()

  let after_disconnect t = t.after_disconnect

  let capture t bufs =
    match t.pcap with
    | None -> Lwt.return ()
    | Some pcap ->
      Lwt_mutex.with_lock t.pcap_m (fun () ->
          let len = List.(fold_left (+) 0 (map Cstruct.len bufs)) in
          let time = Unix.gettimeofday () in
          let secs = Int32.of_float time in
          let usecs = Int32.of_float (1e6 *. (time -. (floor time))) in
          let buf = Cstruct.create Pcap.sizeof_pcap_packet in
          let open Pcap.LE in
          set_pcap_packet_ts_sec buf secs;
          set_pcap_packet_ts_usec buf usecs;
          set_pcap_packet_incl_len buf @@ Int32.of_int len;
          set_pcap_packet_orig_len buf @@ Int32.of_int len;
          really_write pcap (Cstruct.to_string buf |> Bytes.of_string);
          List.iter (fun buf -> really_write pcap (Cstruct.to_string buf |> Bytes.of_string)) bufs;
          match t.pcap_size_limit with
          | None -> Lwt.return () (* no limit *)
          | Some limit ->
            let limit = Int64.(sub limit (of_int len)) in
            t.pcap_size_limit <- Some limit;
            if limit < 0L then stop_capture_already_locked t;
            Lwt.return_unit
        )

  let writev t bufs =
    Lwt_mutex.with_lock t.write_m (fun () ->
        capture t bufs >>= fun () ->
        let len = List.(fold_left (+) 0 (map Cstruct.len bufs)) in
        if len > (t.mtu + ethernet_header_length) then begin
          Log.err (fun f ->
              f "%s Dropping over-large ethernet frame, length = %d, mtu = \
                 %d" t.log_prefix len t.mtu
            );
          Lwt_result.return ()
        end else begin
          let buf = Cstruct.create Packet.sizeof in
          Packet.marshal len buf;
          match t.fd with
          | None    -> Lwt_result.fail `Disconnected
          | Some fd ->
            Channel.write_buffer fd buf;
            Log.debug (fun f ->
                let b = Buffer.create 128 in
                List.iter (Cstruct.hexdump_to_buffer b) bufs;
                f "sending\n%s" (Buffer.contents b)
              );
            List.iter (Channel.write_buffer fd) bufs;
            Channel.flush fd >|= function
            | Ok ()   -> Ok ()
            | Error e -> Error (`Channel e)
        end
      )

  let err_eof t =
    Log.info (fun f -> f "%s.listen: read EOF so closing connection" t.log_prefix);
    disconnect t >>= fun () ->
    Lwt.return false

  let err_unexpected t pp e =
    Log.err (fun f ->
        f "%s listen: caught unexpected %a: disconnecting" t.log_prefix pp e);
    disconnect t >>= fun () ->
    Lwt.return false

  let with_fd t f = match t.fd with
  | None    -> Lwt.return false
  | Some fd -> f fd

  let with_read t x f =
    x >>= function
    | Error e      -> err_unexpected t Channel.pp_error e
    | Ok `Eof      -> err_eof t
    | Ok (`Data x) -> f x

  let with_msg t x f =
    match x with
    | Error (`Msg e) -> err_unexpected t Fmt.string e
    | Ok x           -> f x

  let listen_nocancel t new_callback =
    Log.info (fun f -> f "%s.listen: rebinding the primary listen callback" t.log_prefix);
    t.callback <- new_callback;

    let last_error_log = ref 0. in
    let rec loop () =
      (with_fd t @@ fun fd ->
       with_read t (Channel.read_exactly ~len:Packet.sizeof fd) @@ fun bufs ->
       let read_header = Cstruct.concat bufs in
       with_msg t (Packet.unmarshal read_header) @@ fun (len, _) ->
       with_read t (Channel.read_exactly ~len fd) @@ fun bufs ->
       capture t bufs >>= fun () ->
       Log.debug (fun f ->
           let b = Buffer.create 128 in
           List.iter (Cstruct.hexdump_to_buffer b) bufs;
           f "received%s" (Buffer.contents b)
         );
       let buf = Cstruct.concat bufs in
       let callback buf =
         Lwt.catch (fun () -> t.callback buf)
           (function
           | e ->
             let now = Unix.gettimeofday () in
             if (now -. !last_error_log) > 30. then begin
               Log.err (fun f ->
                   f "%s.listen callback caught %a" t.log_prefix Fmt.exn e);
               last_error_log := now;
             end;
             Lwt.return_unit
           )
       in
       Lwt.async (fun () -> callback buf);
       List.iter (fun callback ->
           Lwt.async (fun () -> callback buf)
         ) t.listeners;
       Lwt.return true
      ) >>= function
      | true  -> loop ()
      | false -> Lwt.return ()
    in
    begin
      if not t.listening then begin
        t.listening <- true;
        Log.info (fun f -> f "%s.listen: starting event loop" t.log_prefix);
        loop ()
      end else begin
        (* Block forever without running a second loop() *)
        Log.info (fun f -> f "%s.listen: blocking until disconnect" t.log_prefix);
        t.after_disconnect
        >>= fun () ->
        Log.info (fun f -> f "%s.listen: disconnected" t.log_prefix);
        Lwt.return_unit
      end
    end
    >>= fun () ->
    Log.info (fun f -> f "%s.listen returning Ok()" t.log_prefix);
    Lwt.return (Ok ())

  let listen t new_callback =
    let task, u = Lwt.task () in
    (* There is a clash over the Netif.listen callbacks between the DHCP client (which
       wants ethernet frames) and the rest of the TCP/IP stack. It seems to work
       usually by accident: first the DHCP client calls `listen`, performs a transaction
       and then the main stack calls `listen` and this overrides the DHCP client listen.
       Unfortunately the DHCP client calls `cancel` after 4s which can ripple through
       and cancel the ethernet `read`. We work around that by ignoring `cancel`. *)
    Lwt.on_cancel task (fun () ->
      Log.warn (fun f -> f "%s.listen: ignoring Lwt.cancel (called from the DHCP client)" t.log_prefix);
    );
    let _ =
      listen_nocancel t new_callback
      >>= fun x ->
      Lwt.wakeup_later u x;
      Lwt.return_unit
    in
    task

  let write t buf =
    Lwt_mutex.with_lock t.write_m (fun () ->
        capture t [ buf ] >>= fun () ->
        let len = Cstruct.len buf in
        if len > (t.mtu + ethernet_header_length) then begin
          Log.err (fun f ->
              f "%s Dropping over-large ethernet frame, length = %d, mtu = \
                 %d" t.log_prefix len t.mtu
            );
          Lwt.return (Ok ())
        end else begin
          if Cstruct.len t.write_header < Packet.sizeof then begin
            t.write_header <- Cstruct.create (1024 * Packet.sizeof)
          end;
          Packet.marshal len t.write_header;
          match t.fd with
          | None    -> Lwt.return (Error `Disconnected)
          | Some fd ->
            Channel.write_buffer fd
              (Cstruct.sub t.write_header 0 Packet.sizeof);
            t.write_header <- Cstruct.shift t.write_header Packet.sizeof;
            Log.debug (fun f ->
                let b = Buffer.create 128 in
                Cstruct.hexdump_to_buffer b buf;
                f "sending%s" (Buffer.contents b)
              );
            Channel.write_buffer fd buf;
            Channel.flush fd >|= function
            | Ok ()   -> Ok ()
            | Error e -> Error (`Channel e)
        end)

  let add_listener t callback = t.listeners <- callback :: t.listeners
  let mac t = t.server_macaddr
  let get_stats_counters t = t.stats
  let reset_stats_counters t = Mirage_net.Stats.reset t.stats

end

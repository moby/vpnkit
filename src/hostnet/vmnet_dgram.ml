open Lwt.Infix

let src =
  let src = Logs.Src.create "vmnet_dgram" ~doc:"vmnet_dgram" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)
open Vmnet_proto

module Make (C : Sig.UNIX_DGRAM) = struct
  type error = Mirage_net.Net.error

  let pp_error ppf = function
    | #Mirage_net.Net.error as e -> Mirage_net.Net.pp_error ppf e

  let failf fmt = Fmt.kstr (fun e -> Lwt_result.fail (`Msg e)) fmt

  type t = {
    mutable fd : C.flow option;
    stats : Mirage_net.stats;
    client_uuid : Uuidm.t;
    client_macaddr : Macaddr.t;
    server_macaddr : Macaddr.t;
    mtu : int;
    write_m : Lwt_mutex.t;
    mutable pcap : Unix.file_descr option;
    mutable pcap_size_limit : int64 option;
    pcap_m : Lwt_mutex.t;
    mutable listeners : (Cstruct.t -> unit Lwt.t) list;
    mutable listening : bool;
    after_disconnect : unit Lwt.t;
    after_disconnect_u : unit Lwt.u;
    (* NB: The Mirage DHCP client calls `listen` and then later the
       Tcp_direct_direct will do the same. This behaviour seems to be
       undefined, but common implementations adopt a last-caller-wins
       semantic. This is the last caller wins callback *)
    mutable callback : Cstruct.t -> unit Lwt.t;
    log_prefix : string;
  }

  let get_client_uuid t = t.client_uuid
  let get_client_macaddr t = t.client_macaddr
  let with_msg x f = match x with Ok x -> f x | Error _ as e -> Lwt.return e
  let server_log_prefix = "Vmnet_dgram.Server"
  let client_log_prefix = "Vmnet_dgram.Client"

  let read_exactly len flow =
    C.recv flow >>= fun buf ->
    if len <> Cstruct.length buf then
      Lwt.fail_with
        (Printf.sprintf "recv: expected length is %d but only received %d" len
           (Cstruct.length buf))
    else Lwt.return buf

  let server_negotiate ~fd ~connect_client_fn ~mtu =
    let assign_uuid_ip uuid ip =
      connect_client_fn uuid ip >>= fun mac ->
      match mac with
      | Error (`Msg msg) ->
          let buf = Cstruct.create Response.sizeof in
          let (_ : Cstruct.t) = Response.marshal (Disconnect msg) buf in
          Log.err (fun f ->
              f "%s.negotiate: disconnecting client, reason: %s"
                server_log_prefix msg);
          C.send fd buf >>= fun () ->
          failf "%s.negotiate: disconnecting client, reason: %s "
            server_log_prefix msg
      | Ok client_macaddr ->
          let vif = Vif.create client_macaddr mtu () in
          let buf = Cstruct.create Response.sizeof in
          let (_ : Cstruct.t) = Response.marshal (Vif vif) buf in
          Log.info (fun f ->
              f "%s.negotiate: sending %s" server_log_prefix (Vif.to_string vif));
          C.send fd buf >>= fun () -> Lwt_result.return (uuid, client_macaddr)
    in
    read_exactly Init.sizeof fd >>= fun buf ->
    let init, _ = Init.unmarshal buf in
    Log.info (fun f ->
        f "%s.negotiate: received %s" server_log_prefix (Init.to_string init));
    match init.version with
    | 22l -> (
        let (_ : Cstruct.t) = Init.marshal Init.default buf in
        C.send fd buf >>= fun () ->
        read_exactly Command.sizeof fd >>= fun buf ->
        with_msg (Command.unmarshal buf) @@ fun (command, _) ->
        Log.info (fun f ->
            f "%s.negotiate: received %s" server_log_prefix
              (Command.to_string command));
        match command with
        | Command.Bind_ipv4 _ ->
            let buf = Cstruct.create Response.sizeof in
            let (_ : Cstruct.t) =
              Response.marshal (Disconnect "Unsupported command Bind_ipv4") buf
            in
            C.send fd buf >>= fun () ->
            failf "%s.negotiate: unsupported command Bind_ipv4"
              server_log_prefix
        | Command.Ethernet uuid -> assign_uuid_ip uuid None
        | Command.Preferred_ipv4 (uuid, ip) -> assign_uuid_ip uuid (Some ip))
    | x ->
        let (_ : Cstruct.t) = Init.marshal Init.default buf in
        (* write our version before disconnecting *)
        C.send fd buf >>= fun () ->
        Log.err (fun f ->
            f
              "%s: Client requested protocol version %s, server only supports \
               version %s"
              server_log_prefix (Int32.to_string x)
              (Int32.to_string Init.default.version));
        Lwt_result.fail (`Msg "Client requested unsupported protocol version")

  let client_negotiate ~uuid ?preferred_ip ~fd () =
    let buf = Cstruct.create Init.sizeof in
    let (_ : Cstruct.t) = Init.marshal Init.default buf in
    C.send fd buf >>= fun () ->
    read_exactly Init.sizeof fd >>= fun buf ->
    let init, _ = Init.unmarshal buf in
    Log.info (fun f ->
        f "%s.negotiate: received %s" client_log_prefix (Init.to_string init));
    match init.version with
    | 22l -> (
        let buf = Cstruct.create Command.sizeof in
        let (_ : Cstruct.t) =
          match preferred_ip with
          | None -> Command.marshal (Command.Ethernet uuid) buf
          | Some ip -> Command.marshal (Command.Preferred_ipv4 (uuid, ip)) buf
        in
        C.send fd buf >>= fun () ->
        read_exactly Response.sizeof fd >>= fun buf ->
        let open Lwt_result.Infix in
        Lwt.return (Response.unmarshal buf) >>= fun (response, _) ->
        match response with
        | Vif vif ->
            Log.debug (fun f ->
                f "%s.negotiate: vif %s" client_log_prefix (Vif.to_string vif));
            Lwt_result.return vif
        | Disconnect reason ->
            let msg = "Server disconnected with reason: " ^ reason in
            Log.err (fun f -> f "%s.negotiate: %s" client_log_prefix msg);
            Lwt_result.fail (`Msg msg))
    | x ->
        Log.err (fun f ->
            f "%s: Server requires protocol version %s, we have %s"
              client_log_prefix (Int32.to_string x)
              (Int32.to_string Init.default.version));
        Lwt_result.fail
          (`Msg "Server does not support our version of the protocol")

  (* Use blocking I/O here so we can avoid Using Lwt_unix or Uwt. Ideally we
     would use a FLOW handle referencing a file/stream. *)
  let really_write fd str =
    let rec loop ofs =
      if ofs = Bytes.length str then ()
      else
        let n = Unix.write fd str ofs (Bytes.length str - ofs) in
        loop (ofs + n)
    in
    loop 0

  let start_capture t ?size_limit filename =
    Lwt_mutex.with_lock t.pcap_m (fun () ->
        (match t.pcap with Some fd -> Unix.close fd | None -> ());
        let fd =
          Unix.openfile filename
            [ Unix.O_WRONLY; Unix.O_TRUNC; Unix.O_CREAT ]
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
        Lwt.return ())

  let stop_capture_already_locked t =
    match t.pcap with
    | None -> ()
    | Some fd ->
        Unix.close fd;
        t.pcap <- None;
        t.pcap_size_limit <- None

  let stop_capture t =
    Lwt_mutex.with_lock t.pcap_m (fun () ->
        stop_capture_already_locked t;
        Lwt.return_unit)

  let make ~client_macaddr ~server_macaddr ~mtu ~client_uuid ~log_prefix fd =
    let fd = Some fd in
    let stats = Mirage_net.Stats.create () in
    let write_m = Lwt_mutex.create () in
    let pcap = None in
    let pcap_size_limit = None in
    let pcap_m = Lwt_mutex.create () in
    let listeners = [] in
    let listening = false in
    let after_disconnect, after_disconnect_u = Lwt.task () in
    let callback _ = Lwt.return_unit in
    {
      fd;
      stats;
      client_macaddr;
      client_uuid;
      server_macaddr;
      mtu;
      write_m;
      pcap;
      pcap_size_limit;
      pcap_m;
      listeners;
      listening;
      after_disconnect;
      after_disconnect_u;
      callback;
      log_prefix;
    }

  type fd = C.flow

  let of_fd ~connect_client_fn ~server_macaddr ~mtu fd =
    let open Lwt_result.Infix in
    server_negotiate ~fd ~connect_client_fn ~mtu
    >>= fun (client_uuid, client_macaddr) ->
    let t =
      make ~client_macaddr ~server_macaddr ~mtu ~client_uuid
        ~log_prefix:server_log_prefix fd
    in
    Lwt_result.return t

  let client_of_fd ~uuid ?preferred_ip ~server_macaddr flow =
    let open Lwt_result.Infix in
    client_negotiate ~uuid ?preferred_ip ~fd:flow () >>= fun vif ->
    let t =
      make ~client_macaddr:server_macaddr ~server_macaddr:vif.Vif.client_macaddr
        ~mtu:vif.Vif.mtu ~client_uuid:uuid ~log_prefix:client_log_prefix flow
    in
    Lwt_result.return t

  let disconnect t =
    match t.fd with
    | None -> Lwt.return ()
    | Some _fd ->
        Log.info (fun f -> f "%s.disconnect" t.log_prefix);
        t.fd <- None;
        Log.debug (fun f -> f "%s.disconnect flushing channel" t.log_prefix);
        Lwt.wakeup_later t.after_disconnect_u ();
        Lwt.return_unit

  let after_disconnect t = t.after_disconnect

  let capture t bufs =
    match t.pcap with
    | None -> Lwt.return ()
    | Some pcap ->
        Lwt_mutex.with_lock t.pcap_m (fun () ->
            let len = List.(fold_left ( + ) 0 (map Cstruct.length bufs)) in
            let time = Unix.gettimeofday () in
            let secs = Int32.of_float time in
            let usecs = Int32.of_float (1e6 *. (time -. floor time)) in
            let buf = Cstruct.create Pcap.sizeof_pcap_packet in
            let open Pcap.LE in
            set_pcap_packet_ts_sec buf secs;
            set_pcap_packet_ts_usec buf usecs;
            set_pcap_packet_incl_len buf @@ Int32.of_int len;
            set_pcap_packet_orig_len buf @@ Int32.of_int len;
            really_write pcap (Cstruct.to_string buf |> Bytes.of_string);
            List.iter
              (fun buf ->
                really_write pcap (Cstruct.to_string buf |> Bytes.of_string))
              bufs;
            match t.pcap_size_limit with
            | None -> Lwt.return () (* no limit *)
            | Some limit ->
                let limit = Int64.(sub limit (of_int len)) in
                t.pcap_size_limit <- Some limit;
                if limit < 0L then stop_capture_already_locked t;
                Lwt.return_unit)

  let with_fd t f = match t.fd with None -> Lwt.return false | Some fd -> f fd

  let listen_nocancel t new_callback =
    Log.info (fun f ->
        f "%s.listen: rebinding the primary listen callback" t.log_prefix);
    t.callback <- new_callback;

    let last_error_log = ref 0. in
    let rec loop () =
      ( with_fd t @@ fun fd ->
        C.recv fd >>= fun buf ->
        capture t [ buf ] >>= fun () ->
        Log.debug (fun f ->
            let b = Buffer.create 128 in
            Cstruct.hexdump_to_buffer b buf;
            f "received%s" (Buffer.contents b));
        let callback buf =
          Lwt.catch
            (fun () -> t.callback buf)
            (function
              | e ->
                  let now = Unix.gettimeofday () in
                  if now -. !last_error_log > 30. then (
                    Log.err (fun f ->
                        f "%s.listen callback caught %a" t.log_prefix Fmt.exn e);
                    last_error_log := now);
                  Lwt.return_unit)
        in
        Lwt.async (fun () -> callback buf);
        List.iter
          (fun callback -> Lwt.async (fun () -> callback buf))
          t.listeners;
        Lwt.return true )
      >>= function
      | true -> loop ()
      | false -> Lwt.return ()
    in
    (if not t.listening then (
     t.listening <- true;
     Log.info (fun f -> f "%s.listen: starting event loop" t.log_prefix);
     loop ())
    else (
      (* Block forever without running a second loop() *)
      Log.info (fun f -> f "%s.listen: blocking until disconnect" t.log_prefix);
      t.after_disconnect >>= fun () ->
      Log.info (fun f -> f "%s.listen: disconnected" t.log_prefix);
      Lwt.return_unit))
    >>= fun () ->
    Log.info (fun f -> f "%s.listen returning Ok()" t.log_prefix);
    Lwt.return (Ok ())

  let listen t ~header_size:_ new_callback =
    let task, u = Lwt.task () in
    (* There is a clash over the Netif.listen callbacks between the DHCP client (which
       wants ethernet frames) and the rest of the TCP/IP stack. It seems to work
       usually by accident: first the DHCP client calls `listen`, performs a transaction
       and then the main stack calls `listen` and this overrides the DHCP client listen.
       Unfortunately the DHCP client calls `cancel` after 4s which can ripple through
       and cancel the ethernet `read`. We work around that by ignoring `cancel`. *)
    Lwt.on_cancel task (fun () ->
        Log.warn (fun f ->
            f "%s.listen: ignoring Lwt.cancel (called from the DHCP client)"
              t.log_prefix));
    let _ =
      listen_nocancel t new_callback >>= fun x ->
      Lwt.wakeup_later u x;
      Lwt.return_unit
    in
    task

  let write t ~size fill =
    Lwt_mutex.with_lock t.write_m (fun () ->
        let allocated = Cstruct.create (size + t.mtu) in
        let len = fill allocated in
        let buf = Cstruct.sub allocated 0 len in
        capture t [ buf ] >>= fun () ->
        if len > t.mtu + ethernet_header_length then (
          Log.err (fun f ->
              f "%s Dropping over-large ethernet frame, length = %d, mtu = %d"
                t.log_prefix len t.mtu);
          Lwt.return (Ok ()))
        else
          match t.fd with
          | None -> Lwt.return (Error `Disconnected)
          | Some fd ->
              Log.debug (fun f ->
                  let b = Buffer.create 128 in
                  Cstruct.hexdump_to_buffer b buf;
                  f "sending%s" (Buffer.contents b));
              C.send fd buf >>= fun () -> Lwt.return (Ok ()))

  let add_listener t callback = t.listeners <- callback :: t.listeners
  let mac t = t.server_macaddr
  let mtu t = t.mtu
  let get_stats_counters t = t.stats
  let reset_stats_counters t = Mirage_net.Stats.reset t.stats
end

let%test_unit "negotiate" =
  if Sys.os_type <> "Win32" then
    let module V = Make (Host_unix_dgram) in
    Lwt_main.run
      (let address = "/tmp/vmnet_dgram.sock" in
       (try Unix.unlink address with Unix.Unix_error (Unix.ENOENT, _, _) -> ());
       let expected_uuid = Uuidm.v `V4 in
       let expected_mtu = 1500 in
       let expected_mac = Macaddr.of_string_exn "C0:FF:EE:C0:FF:EE" in
       Host_unix_dgram.bind address >>= fun server ->
       Host_unix_dgram.listen server (fun flow ->
           let connect_client_fn _uuid _ip = Lwt.return (Ok expected_mac) in
           V.server_negotiate ~fd:flow ~connect_client_fn ~mtu:expected_mtu
           >>= function
           | Error (`Msg m) -> failwith m
           | Ok (_uuid, _mac) -> Lwt.return_unit);
       Host_unix_dgram.connect address >>= fun flow ->
       V.client_negotiate ~uuid:expected_uuid ~fd:flow () >>= function
       | Error (`Msg m) -> failwith m
       | Ok vif ->
           if vif.mtu <> expected_mtu then
             failwith
               (Printf.sprintf "vif.mtu (%d) <> expected_mtu (%d)" vif.mtu
                  expected_mtu);
           if Macaddr.compare vif.client_macaddr expected_mac <> 0 then
             failwith
               (Printf.sprintf "vif.client_macaddr (%s) <> expected_mac (%s)"
                  (Macaddr.to_string vif.client_macaddr)
                  (Macaddr.to_string expected_mac));
           Lwt.return_unit)

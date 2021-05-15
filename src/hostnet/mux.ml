open Lwt.Infix

let src =
  let src = Logs.Src.create "mux" ~doc:"Mirage TCP/IP <-> socket proxy" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module DontCareAboutStats = struct
  let get_stats_counters _ = Mirage_net.Stats.create ()
  let reset_stats_counters _ = ()
end

module ObviouslyCommon = struct

  type error = [Mirage_net.Net.error | `Unknown of string]

  let pp_error ppf = function
  | #Mirage_net.Net.error as e -> Mirage_net.Net.pp_error ppf e
  | `Unknown s -> Fmt.pf ppf "unknown: %s" s

end

module Make (Netif: Mirage_net.S) = struct

  include DontCareAboutStats
  include ObviouslyCommon

  type rule = Ipaddr.V4.t

  module RuleMap = Map.Make(Ipaddr.V4)

  type callback = Cstruct.t -> unit Lwt.t

  type port = {
    callback: callback;
    mutable last_active_time: float;
  }

  type t = {
    netif: Netif.t;
    mutable rules: port RuleMap.t;
    mutable default_callback: callback;
  }

  let lift_error: ('a, Netif.error) result -> ('a, error) result = function
  | Ok x    -> Ok x
  | Error (#Mirage_net.Net.error as e) -> Error e
  | Error e -> Fmt.kstrf (fun s -> Error (`Unknown s)) "%a" Netif.pp_error e

  let filesystem t =
    let xs =
      RuleMap.fold
        (fun ip t acc ->
           Fmt.strf "%a last_active_time = %.1f" Ipaddr.V4.pp ip
             t.last_active_time
           :: acc
        ) t.rules []
    in
    Vfs.File.ro_of_string (String.concat "\n" xs)

  let remove t rule =
    Log.debug (fun f ->
        f "removing switch port for %s" (Ipaddr.V4.to_string rule));
    t.rules <- RuleMap.remove rule t.rules

  let callback t buf =
    (* Does the packet match any of our rules? *)
    let open Frame in
    match parse [ buf ] with
    | Ok (Ethernet { payload = Ipv4 { dst; _ }; _ }) ->
      if RuleMap.mem dst t.rules then begin
        let port = RuleMap.find dst t.rules in
        port.last_active_time <- Unix.gettimeofday ();
        port.callback buf
      end else begin
        Log.debug (fun f ->
            f "using default callback for packet for %a" Ipaddr.V4.pp dst);
        t.default_callback buf
      end
    | _ ->
      Log.debug (fun f -> f "using default callback for non-IPv4 frame");
      t.default_callback buf

  let connect netif =
    let rules = RuleMap.empty in
    let default_callback = fun _ -> Lwt.return_unit in
    let t = { netif; rules; default_callback } in
    Lwt.async
      (fun () ->
         Netif.listen netif ~header_size:Ethernet_wire.sizeof_ethernet @@ callback t >>= function
         | Ok () -> Lwt.return_unit
         | Error _e ->
           Log.err (fun f -> f "Mux.connect calling Netif.listen: failed");
           Lwt.return_unit
      );
    Lwt.return (Ok t)

  let write t ~size fill = Netif.write t.netif ~size fill >|= lift_error
  let listen t ~header_size:_ callback = t.default_callback <- callback; Lwt.return (Ok ())
  let disconnect t = Netif.disconnect t.netif
  let mac t = Netif.mac t.netif
  let mtu t = Netif.mtu t.netif

  module Port = struct
    include DontCareAboutStats
    include ObviouslyCommon

    type _t = {
      switch: t;
      netif: Netif.t;
      rule: rule;
    }

    let write t ~size fill = Netif.write t.netif ~size fill >|= lift_error

    let listen t ~header_size:_ callback =
      Log.debug (fun f ->
          f "activating switch port for %s" (Ipaddr.V4.to_string t.rule));
      let last_active_time = Unix.gettimeofday () in
      let port = { callback; last_active_time } in
      t.switch.rules <- RuleMap.add t.rule port t.switch.rules;
      Lwt.return (Ok ())

    let disconnect t =
      Log.debug (fun f ->
          f "deactivating switch port for %s" (Ipaddr.V4.to_string t.rule));
      t.switch.rules <- RuleMap.remove t.rule t.switch.rules;
      Lwt.return_unit

    let mac t = Netif.mac t.netif
    let mtu t = Netif.mtu t.netif

    type t = _t
  end

  let port t rule = { Port.switch = t; netif = t.netif; rule }

end

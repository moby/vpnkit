type t =
  | Ethernet: { src: Macaddr.t; dst: Macaddr.t; payload: t } -> t
  | Arp:      { op: [ `Request | `Reply | `Unknown ] } -> t
  | Icmp:     { ty: int; code: int; seq: int; id: int;
                raw: Cstruct.t; payload: t } -> t
  | Ipv4:     { src: Ipaddr.V4.t; dst: Ipaddr.V4.t; dnf: bool; ihl: int;
                raw: Cstruct.t; payload: t } -> t
  | Udp:      { src: int; dst: int; len: int; payload: t } -> t
  | Tcp:      { src: int; dst: int; syn: bool; raw: Cstruct.t; payload: t } -> t
  | Payload:  Cstruct.t -> t
  | Unknown:  t

let ( >>= ) m f = match m with
| Ok x -> f x
| Error x -> Error x

let errorf fmt = Fmt.kstrf (fun e -> Error (`Msg e)) fmt

let need_space_for bufs n description =
  if Cstructs.len bufs < n
  then errorf "buffer is too short for %s: needed %d bytes but only have %d"
      description n (Cstructs.len bufs)
  else Ok ()

let parse bufs =
  try
    need_space_for bufs 14 "ethernet frame"
    >>= fun () ->
    let ethertype  = Cstructs.BE.get_uint16 bufs 12 in
    let dst_option =
      Cstructs.sub bufs 0 6 |> Cstructs.to_string |> Macaddr.of_bytes
    in
    let src_option =
      Cstructs.sub bufs 6 6 |> Cstructs.to_string |> Macaddr.of_bytes
    in
    match dst_option, src_option with
    | None, _ -> errorf "failed to parse ethernet destination MAC"
    | _, None -> errorf "failed to parse ethernet source MAC"
    | Some dst, Some src ->
      let inner = Cstructs.shift bufs 14 in
      ( match ethertype with
      | 0x0800 ->
        need_space_for inner 16 "IP datagram"
        >>= fun () ->
        let vihl  = Cstructs.get_uint8     inner 0 in
        let len   = Cstructs.BE.get_uint16 inner (1 + 1) in
        let off   = Cstructs.BE.get_uint16 inner (1 + 1 + 2 + 2) in
        let proto = Cstructs.get_uint8     inner (1 + 1 + 2 + 2 + 2 + 1) in
        let src   = Cstructs.BE.get_uint32 inner (1 + 1 + 2 + 2 + 2 + 1 + 1 + 2)
                    |> Ipaddr.V4.of_int32 in
        let dst   = Cstructs.BE.get_uint32 inner (1 + 1 + 2 + 2 + 2 + 1 + 1 + 2 + 4)
                    |> Ipaddr.V4.of_int32 in
        let dnf = ((off lsr 8) land 0x40) <> 0 in
        let ihl = vihl land 0xf in
        let raw = Cstructs.to_cstruct inner in
        need_space_for inner (4 * ihl) "IP options"
        >>= fun () ->
        let inner = Cstructs.sub inner (4 * ihl) (len - 4 * ihl) in
        ( match proto with
        | 1 ->
          need_space_for inner 8 "ICMP message"
          >>= fun () ->
          let ty     = Cstructs.get_uint8     inner 0 in
          let code   = Cstructs.get_uint8     inner 1 in
          let _csum   = Cstructs.BE.get_uint16 inner 2 in
          let id     = Cstructs.BE.get_uint16 inner 4 in
          let seq    = Cstructs.BE.get_uint16 inner 6 in
          let payload = Cstructs.shift         inner 8 |> Cstructs.to_cstruct in
          Ok (Icmp { raw; ty; code; id; seq; payload = Payload payload })
        | 6 ->
          need_space_for inner 14 "TCP header"
          >>= fun () ->
          let src     = Cstructs.BE.get_uint16 inner 0 in
          let dst     = Cstructs.BE.get_uint16 inner 2 in
          let offres  = Cstructs.get_uint8     inner (2 + 2 + 4 + 4) in
          let flags   = Cstructs.get_uint8     inner (2 + 2 + 4 + 4 + 1) in
          need_space_for inner ((offres lsr 4) * 4) "TCP options"
          >>= fun () ->
          let payload = Cstructs.shift         inner ((offres lsr 4) * 4)
                        |> Cstructs.to_cstruct in
          let syn = (flags land (1 lsl 1)) > 0 in
          Ok (Tcp { src; dst; syn; raw = Cstructs.to_cstruct inner;
                    payload = Payload payload })
        | 17 ->
          need_space_for inner 8 "UDP header"
          >>= fun () ->
          let src     = Cstructs.BE.get_uint16 inner 0 in
          let dst     = Cstructs.BE.get_uint16 inner 2 in
          let len     = Cstructs.BE.get_uint16 inner 4 in
          let payload = Cstructs.shift         inner 8 |> Cstructs.to_cstruct in
          let len = len - 8 in (* subtract header length *)
          Ok (Udp { src; dst; len; payload = Payload payload })
        | _ ->
          Ok Unknown )
        >>= fun payload ->
        Ok (Ipv4 { src; dst; dnf; ihl; raw; payload })
      | 0x0806 ->
        need_space_for inner 2 "ARP header"
        >>= fun () ->
        let code    = Cstructs.BE.get_uint16 inner 6 in
        let op = match code with 1 -> `Request | 2 -> `Reply | _ -> `Unknown in
        Ok (Arp { op })
      | _ ->
        (* This is going to be quite common e.g. with IPv6 *)
        Ok Unknown )
      >>= fun payload ->
      Ok (Ethernet { src; dst; payload })
  with e ->
    errorf "Failed to parse ethernet frame: %a" Fmt.exn e

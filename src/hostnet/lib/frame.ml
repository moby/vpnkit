
type t =
  | Ethernet: { src: Macaddr.t; dst: Macaddr.t; payload: t } -> t
  | Arp:      { op: [ `Request | `Reply | `Unknown ] } -> t
  | Ipv4:     { src: Ipaddr.V4.t; dst: Ipaddr.V4.t; dnf: bool; ihl: int; raw: Cstruct.t; payload: t } -> t
  | Udp:      { src: int; dst: int; len: int; payload: t } -> t
  | Tcp:      { src: int; dst: int; syn: bool; raw: Cstruct.t; payload: t } -> t
  | Payload:  Cstruct.t -> t

open Result
let ( >>= ) m f = match m with
  | Ok x -> f x
  | Error x -> Error x

let parse buf =
  if Cstruct.len buf < 14
  then Error (`Msg "too short to be an ethernet frame")
  else begin
    let ethertype  = Cstruct.BE.get_uint16 buf 12 in
    let dst_option = Cstruct.sub buf 0 6 |> Cstruct.to_string |> Macaddr.of_bytes in
    let src_option = Cstruct.sub buf 6 6 |> Cstruct.to_string |> Macaddr.of_bytes in
    match dst_option, src_option with
    | None, _ -> Error (`Msg "failed to parse ethernet destination MAC")
    | _, None -> Error (`Msg "failed to parse ethernet source MAC")
    | Some src, Some dst ->
      let inner = Cstruct.shift buf 14 in
      ( match ethertype with
        | 0x0800 ->
          let vihl  = Cstruct.get_uint8     inner 0 in
          let len   = Cstruct.BE.get_uint16 inner (1 + 1) in
          let off   = Cstruct.BE.get_uint16 inner (1 + 1 + 2 + 2) in
          let proto = Cstruct.get_uint8     inner (1 + 1 + 2 + 2 + 2 + 1) in
          let src   = Cstruct.BE.get_uint32 inner (1 + 1 + 2 + 2 + 2 + 1 + 1 + 2) |> Ipaddr.V4.of_int32 in
          let dst   = Cstruct.BE.get_uint32 inner (1 + 1 + 2 + 2 + 2 + 1 + 1 + 2 + 4) |> Ipaddr.V4.of_int32 in
          let dnf = ((off lsr 8) land 0x40) <> 0 in
          let ihl = vihl land 0xf in
          let raw = inner in
          let inner = Cstruct.sub inner (4 * ihl) (len - 4 * ihl) in
          ( match proto with
            | 6 ->
              let src     = Cstruct.BE.get_uint16 inner 0 in
              let dst     = Cstruct.BE.get_uint16 inner 2 in
              let offres  = Cstruct.get_uint8     inner (2 + 2 + 4 + 4) in
              let flags   = Cstruct.get_uint8     inner (2 + 2 + 4 + 4 + 1) in
              let payload = Cstruct.shift         inner ((offres lsr 4) * 4) in
              let syn = (flags land (1 lsl 1)) > 0 in
              Ok (Tcp { src; dst; syn; raw = inner; payload = Payload payload })
            | 17 ->
              let src     = Cstruct.BE.get_uint16 inner 0 in
              let dst     = Cstruct.BE.get_uint16 inner 2 in
              let len     = Cstruct.BE.get_uint16 inner 4 in
              let payload = Cstruct.shift         inner 8 in
              let len = len - 8 in (* subtract header length *)
              Ok (Udp { src; dst; len; payload = Payload payload })
            | _ ->
              Error (`Msg (Printf.sprintf "unknown IPv4 protocol type %d" proto)) )
          >>= fun payload ->
          Ok (Ipv4 { src; dst; dnf; ihl; raw; payload })
        | 0x0806 ->
          let code    = Cstruct.BE.get_uint16 inner 6 in
          let op = match code with 1 -> `Request | 2 -> `Reply | _ -> `Unknown in
          Ok (Arp { op })
        | _ ->
          Error (`Msg (Printf.sprintf "unknown ethertype %d" ethertype)) )
      >>= fun payload ->
      Ok (Ethernet { src; dst; payload })

  end

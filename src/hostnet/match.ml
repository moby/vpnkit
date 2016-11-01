let src =
  let src = Logs.Src.create "capture" ~doc:"capture network traffic" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

type t = Cstruct.t list -> bool

let all _ = true

let (or) a b bufs =
  a bufs || (b bufs)

(* Treat any big enough frame as a potential ethernet frame *)
let ethernet f bufs = (Cstructs.len bufs >= 14) && (f bufs)

let optional opt x = match opt with
  | None -> true
  | Some x' -> x' = x

let arp ?opcode () bufs =
  let ethertype = Cstructs.BE.get_uint16 bufs 12 in
  let payload = Cstructs.shift bufs 14 in
  let op = Cstructs.BE.get_uint16 payload 6 in
  let opcode' = match op with 1 -> `Request | 2 -> `Reply | _ -> `Unknown in
  ethertype = 0x0806 && (optional opcode opcode')

let ipv4 ?src ?dst () f bufs =
  let ethertype = Cstructs.BE.get_uint16 bufs 12 in
  let payload = Cstructs.shift bufs 14 in
  let src' = Ipaddr.V4.of_int32 @@ Cstructs.BE.get_uint32 payload (1 + 1 + 2 + 2 + 2 + 1 + 1 + 2) in
  let dst' = Ipaddr.V4.of_int32 @@ Cstructs.BE.get_uint32 payload (1 + 1 + 2 + 2 + 2 + 1 + 1 + 2 + 4) in
  ethertype = 0x0800 && (optional src src') && (optional dst dst') && (f payload)

let udp ?src ?dst () f bufs =
  let proto   = Cstructs.get_uint8    bufs    (1 + 1 + 2 + 2 + 2 + 1) in
  let payload = Cstructs.shift        bufs    (1 + 1 + 2 + 2 + 2 + 1 + 1 + 2 + 4 + 4) in
  let src'    = Cstructs.BE.get_uint16 payload 0 in
  let dst'    = Cstructs.BE.get_uint16 payload 2 in
  proto = 17 && (optional src src') && (optional dst dst') && (f @@ Cstructs.shift payload 16)

let tcp ?src ?dst ?fin ?syn ?rst ?psh ?ack ?urg ?ece ?cwr () f bufs =
  let vihl    = Cstructs.get_uint8    bufs    0 in
  let proto   = Cstructs.get_uint8    bufs    (1 + 1 + 2 + 2 + 2 + 1) in
  let payload = Cstructs.shift        bufs    (4 * (vihl land 0xf)) in
  let src'    = Cstructs.BE.get_uint16 payload 0 in
  let dst'    = Cstructs.BE.get_uint16 payload 2 in
  let flags   = Cstructs.get_uint8    payload    (2 + 2 + 4 + 4 + 1) in
  let fin'    = (flags land (1 lsl 0)) > 0 in
  let syn'    = (flags land (1 lsl 1)) > 0 in
  let rst'    = (flags land (1 lsl 2)) > 0 in
  let psh'    = (flags land (1 lsl 3)) > 0 in
  let ack'    = (flags land (1 lsl 4)) > 0 in
  let urg'    = (flags land (1 lsl 5)) > 0 in
  let ece'    = (flags land (1 lsl 6)) > 0 in
  let cwr'    = (flags land (1 lsl 7)) > 0 in
  proto = 6
  && (optional src src') && (optional dst dst')
  && (optional fin fin') && (optional syn syn')
  && (optional rst rst') && (optional psh psh')
  && (optional ack ack') && (optional urg urg')
  && (optional ece ece') && (optional cwr cwr')
  && (f @@ Cstructs.shift payload 16)

let bufs t bufs = t bufs

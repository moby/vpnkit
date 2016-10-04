let src =
  let src = Logs.Src.create "capture" ~doc:"capture network traffic" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Cstructs = struct

  type t = Cstruct.t list

  let pp_t ppf t =
    List.iter (fun t ->
      Format.fprintf ppf "[%d,%d](%d)" t.Cstruct.off t.Cstruct.len (Bigarray.Array1.dim t.Cstruct.buffer)
    ) t

  let len = List.fold_left (fun acc c -> Cstruct.len c + acc) 0

  let err fmt =
    let b = Buffer.create 20 in                         (* for thread safety. *)
    let ppf = Format.formatter_of_buffer b in
    let k ppf = Format.pp_print_flush ppf (); invalid_arg (Buffer.contents b) in
    Format.kfprintf k ppf fmt

  let rec shift t x =
    if x = 0 then t else match t with
    | [] -> err "Cstructs.shift %a %d" pp_t t x
    | y :: ys ->
      let y' = Cstruct.len y in
      if y' > x
      then Cstruct.shift y x :: ys
      else shift ys (x - y')

  (* Return a Cstruct.t representing (off, len) by either returning a reference
     or making a copy if the value is split across two fragments. Ideally this
     would return a string rather than a Cstruct.t for efficiency *)
  let get f t off len =
    let t' = shift t off in
    match t' with
    | x :: xs ->
      (* Return a reference to the existing buffer *)
      if Cstruct.len x >= len
      then Cstruct.sub x 0 len
      else begin
        (* Copy into a fresh buffer *)
        let rec copy remaining frags =
          if Cstruct.len remaining > 0
          then match frags with
            | [] ->
              err "invalid bounds in Cstructs.%s %a off=%d len=%d" f pp_t t off len
            | x :: xs ->
              let to_copy = min (Cstruct.len x) (Cstruct.len remaining) in
              Cstruct.blit x 0 remaining 0 to_copy;
              (* either we've copied all of x, or we've filled the remaining buffer *)
              copy (Cstruct.shift remaining to_copy) xs in
        let result = Cstruct.create len in
        copy result (x :: xs);
        result
      end
    | [] ->
      err "invalid bounds in Cstructs.%s %a off=%d len=%d" f pp_t t off len

  let get_uint8 t off = Cstruct.get_uint8 (get "get_uint8"  t off 1) 0

  module BE = struct
    open Cstruct.BE
    let get_uint16 t off = get_uint16 (get "get_uint16" t off 2) 0
    let get_uint32 t off = get_uint32 (get "get_uint32" t off 4) 0
  end

end

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

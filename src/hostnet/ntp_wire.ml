(* the NTP RFCs use both greek letters ("theta") and words ("offset") to refer
 * to the same things and it is frustrating. here is the correspondence between
 * the two:
     * clock offset     = theta
     * round-trip delay = delta
     * dispersion       = epsilon
     * peer jitter      = psi
 *
 * variables with _i suffix are samples
 * variables with _e suffix are estimates/averages
 * variables beginning with ne_ (near end) are times measured/struck on/by our host
 * variables beginning with fe_ (far  end) are times measured/struck on/by the server we query
 *
 * Therefore, when we create a packet, we strike   ne_transmit
 * when it arrives at the server,      it strikes  fe_receive
 * when it sends back a reply,         it strikes  fe_transmit
 * when we receive the reply,          we strike   ne_receive
 *
 *
 *
 * The NTP protocol is symmetric and simple and yet the official documentation
 * tries its best to obscure the simplicity. Every packet sent by a full
 * implementation contains:

     * a timestamp struck by the sender when the last packet from its interlocutor was received
        (known as "receive timestamp")
     * a timestamp struck by the sender when it is created
        (known as "transmit timestamp")
     * a copy of what was in the "transmit timestamp" field in the last packet received from its interlocutor
        (known as "originator timestamp")

 * Due to the symmetry of the NTP wire protocol, ne_transmit is in the
 * "transmit timestamp" field when we sent a packet but is returned to us in
 * the "origin timestamp" field.
 *
 *
 * We implement a useful and clean subset (that is not SNTP!) of the NTP
 * protocol that only permits use of the server and client modes. Nothing in
 * the NTP wire protocol is asymmetric -- it permits two hosts that are
 * exchanging NTP packets to each measure the offset and delay between each
 * other. However, this symmetry is not needed in either the client or server
 * modes and an implementation without it avoids needless complexity and
 * obtains exactly the same results.
 *
 * Rather, the packets we send when in client mode only have a *single*
 * timestamp field filled out -- the "transmit timestamp" field, with a
 * timestamp we strike when we create that packet. We could actually fill it
 * with a completely random number/nonce and store a nonce->timestamp mapping
 * table locally, as the server does not process it beyond copying it into the
 * "originator timestamp" field in its reply.
 *
 * We don't fill out the other two timestamp fields in the NTP packet that
 * would let the server measure our offset/delay, nor do we fill out the
 * "reference timestamp" field.
 *
 * The server will reply with a packet with the same information in the
 * timestamps as it would for a packet with the "originator" and "receive"
 * timestamps filled -- indeed, the first packet every NTP client sends to a
 * server can't have those fields filled.
 *
 *)


type ts = {
    timestamp:  Cstruct.uint64 [@printer fun fmt -> fprintf fmt "0x%Lx"];
}
[@@deriving show]

let ts_to_int64 ts =
    ts.timestamp

let int64_to_ts timestamp =
    {timestamp}

let to_float a =
    let frac = Int64.of_int32 @@ Int64.to_int32 a.timestamp in   (* I'm so sorry. *)
    let frac = match (frac < 0x0L) with
    | true  -> Int64.add frac 0x100000000L                       (* I'm so so sorry *)
    | false -> frac
    in

    let seconds = Int64.shift_right_logical a.timestamp 32 in

    (Int64.to_float frac) /. (4294967296.0) +. Int64.to_float seconds

type short_ts = {
    seconds: Cstruct.uint16;
    fraction: Cstruct.uint16;
}

let short_ts_to_int32 ts =
    Int32.add (Int32.of_int ts.fraction) (Int32.shift_left (Int32.of_int ts.seconds) 16)

let short_ts_to_float a =
    Int32.to_float (short_ts_to_int32 a)

let int32_to_short_ts i =
    let seconds =  Int32.to_int(Int32.shift_right_logical i 16) in
    let fraction = Int32.to_int(Int32.logand (Int32.of_int 0xffff) i) in
    {seconds; fraction}

type date = {
    era: Cstruct.uint32;
    offset: Cstruct.uint32;
    fraction: Cstruct.uint64;
}

let log_to_float x =
    2. ** (float x)

type span    = Span    of int64 (* span represents a monotonic time value as measured by our clock -- what RFC 5905 calls "process time" *)
type seconds = Seconds of float (* all the statistical calculations are on floats *)

type leap_flavor = NoWarning | Minute61 | Minute59 | Unsync (* leap seconds were a mistake *)
[@@deriving show]

type version = int

type mode = Reserved | SymA | SymP | Client | Server | Broadcast | Control | Private

let lvm_to_int l v m =
    let li = match l with
    | NoWarning -> 0 lsl 6
    | Minute61  -> 1 lsl 6
    | Minute59  -> 2 lsl 6
    | Unsync    -> 3 lsl 6 in
    let vi = v lsl 3 in
    let mi = match m with
    | Reserved  -> 0
    | SymA      -> 1
    | SymP      -> 2
    | Client    -> 3
    | Server    -> 4
    | Broadcast -> 5
    | Control   -> 6
    | Private   -> 7 in

    li + vi + mi


let flags_to_leap       f =
    match f lsr 6 with
    | 0 -> NoWarning
    | 1 -> Minute61
    | 2 -> Minute59
    | 3 -> Unsync
    | _ -> failwith ":("

let flags_to_version    f = (f land 0x38) lsr 3
let flags_to_mode       f =
    match (f land 0x07) with
    | 0 -> Reserved
    | 1 -> SymA
    | 2 -> SymP
    | 3 -> Client
    | 4 -> Server
    | 5 -> Broadcast
    | 6 -> Control
    | 7 -> Private
    | _ -> failwith ":("



type stratum = Invalid | Primary | Secondary of int | Unsynchronized | Reserved of int
[@@deriving show]

let int_to_stratum (i: Cstruct.uint8) = match i with
    | 0 -> Invalid
    | 1 -> Primary
    | n1 when ((n1 > 1) && (n1 < 16)) -> Secondary n1
    | 16 -> Unsynchronized
    | n2  -> Reserved n2

let stratum_to_int s = match s with
    | Invalid -> 0
    | Primary -> 1
    | Secondary n -> n
    | Unsynchronized -> 16
    | Reserved n -> n



[%%cstruct
type ntp = {
    flags:              uint8_t;
    stratum:            uint8_t;
    poll:               int8_t;
    precision:          int8_t;
    root_delay:         uint32_t;
    root_dispersion:    uint32_t;
    refid:              uint32_t;
    reference_ts:       uint64_t;   (* not really an important timestamp *)

    (* the important timestamps *)
                                    (* the below annotations only apply on a packet we're receiving! *)
    origin_ts:          uint64_t;   (* T1: client-measured time when request departs *)
    recv_ts:            uint64_t;   (* T2: server-measured time when request arrives *)
    trans_ts:           uint64_t;   (* T3: server-measured time when reply   departs *)
} [@@big_endian]]


type pkt = {
    leap            : leap_flavor;
    version         : version;
    mode            : mode;
    stratum         : stratum;
    poll            : int;
    precision       : int;
    root_delay      : short_ts;
    root_dispersion : short_ts;
    refid           : int32;
    reference_ts    : ts;
    origin_ts       : ts;
    recv_ts         : ts;
    trans_ts        : ts;
}

let buf_of_pkt p =
    let buf = Cstruct.create sizeof_ntp in
    set_ntp_flags           buf  (lvm_to_int p.leap p.version p.mode);
    set_ntp_stratum         buf     (stratum_to_int p.stratum);
    set_ntp_poll            buf                     p.poll;
    set_ntp_precision       buf                     p.precision;
    set_ntp_root_delay      buf (short_ts_to_int32  p.root_delay);
    set_ntp_root_dispersion buf (short_ts_to_int32  p.root_dispersion);
    set_ntp_refid           buf                     p.refid;
    set_ntp_reference_ts    buf (ts_to_int64        p.reference_ts);
    set_ntp_origin_ts       buf (ts_to_int64        p.origin_ts);
    set_ntp_recv_ts         buf (ts_to_int64        p.recv_ts);
    set_ntp_trans_ts        buf (ts_to_int64        p.trans_ts);

    buf




let pkt_of_buf b =
    if Cstruct.len b <> sizeof_ntp then
        None
    else
        let leap            = get_ntp_flags             b |> flags_to_leap      in
        let version         = get_ntp_flags             b |> flags_to_version   in
        let mode            = get_ntp_flags             b |> flags_to_mode      in
        let stratum         = get_ntp_stratum           b |> int_to_stratum     in
        let poll            = get_ntp_poll              b                       in
        let precision       = get_ntp_precision         b                       in
        let root_delay      = get_ntp_root_delay        b |> int32_to_short_ts  in
        let root_dispersion = get_ntp_root_dispersion   b |> int32_to_short_ts  in
        let refid           = get_ntp_refid             b                       in
        let reference_ts    = get_ntp_reference_ts      b |> int64_to_ts        in
        let origin_ts       = get_ntp_origin_ts         b |> int64_to_ts        in
        let recv_ts         = get_ntp_recv_ts           b |> int64_to_ts        in
        let trans_ts        = get_ntp_trans_ts          b |> int64_to_ts        in
        Some {leap;version;mode; stratum; poll; precision; root_delay; root_dispersion; refid; reference_ts; origin_ts; recv_ts; trans_ts}

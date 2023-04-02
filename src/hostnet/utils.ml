external get_SOMAXCONN: unit -> int = "stub_get_SOMAXCONN"

let somaxconn = ref (get_SOMAXCONN ())

external rtlGenRandom: int -> bytes option = "stub_RtlGenRandom"

external setSocketTTL: Unix.file_descr -> int -> unit = "stub_setSocketTTL"

type buffer = (char, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t

external stub_cstruct_send: Unix.file_descr -> buffer -> int -> int -> int = "stub_cstruct_send"
let cstruct_send fd c = stub_cstruct_send fd c.Cstruct.buffer c.Cstruct.off c.Cstruct.len

external stub_cstruct_recv: Unix.file_descr -> buffer -> int -> int -> int = "stub_cstruct_recv"
let cstruct_recv fd c = stub_cstruct_recv fd c.Cstruct.buffer c.Cstruct.off c.Cstruct.len


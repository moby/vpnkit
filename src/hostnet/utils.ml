
external get_SOMAXCONN: unit -> int = "stub_get_SOMAXCONN"

let somaxconn = ref (get_SOMAXCONN ())

external stub_RtlGenRandom: int -> bytes option = "stub_RtlGenRandom"

let rtlGenRandom len =
  match stub_RtlGenRandom len with
  | None -> None
  | Some buf ->
    let cs = Cstruct.create (String.length buf) in
    Cstruct.blit_from_bytes buf 0 cs 0 (String.length buf);
    Some cs

let random_init () =
  match rtlGenRandom 1024 with
  | Some _ ->
    ()
  | None ->
    Random.self_init ()

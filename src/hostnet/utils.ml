
external get_SOMAXCONN: unit -> int = "stub_get_SOMAXCONN"

let somaxconn = ref (get_SOMAXCONN ())

external stub_CryptGenRandom: int -> bytes option = "stub_CryptGenRandom"

let cryptGenRandom len =
  match stub_CryptGenRandom len with
  | None -> None
  | Some buf ->
    let cs = Cstruct.create (String.length buf) in
    Cstruct.blit_from_bytes buf 0 cs 0 (String.length buf);
    Some cs

open Nocrypto
open Uncommon

let random_init () =
  let g = !Rng.generator in
  let bytes = 1024 in
  match cryptGenRandom bytes with
  | Some entropy ->
    Rng.reseed ~g entropy
  | None ->
    (* From Nocrypto_entropy_unix *)
    let devices = [ "/dev/urandom"; "/dev/random" ] in
    let fs_exists name =
      Unix.(try ignore (stat name); true with Unix_error(Unix.ENOENT, _, _) -> false) in
    let sys_rng =
      try List.find fs_exists devices with Not_found ->
      failwith "Failed to find a /dev/urandom or /dev/random" in
    let read_cs fd n =
      let buf = Bytes.create n in
      let k = Unix.read fd buf 0 n in
      let cs = Cstruct.create k in
      Cstruct.blit_from_bytes buf 0 cs 0 k;
      cs in
    let reseed ~bytes g =
      let rec feed n fd =
        if n > 0 then
          let cs = read_cs fd n in
          Rng.reseed ~g cs;
          feed (n - Cstruct.len cs) fd in
      bracket
        ~init:Unix.(fun () -> openfile sys_rng [O_RDONLY] 0)
        ~fini:Unix.close
        (feed bytes) in
    reseed ~bytes g
type t = Cstruct.t list

let pp_t ppf t =
  List.iter (fun t ->
      Fmt.pf ppf "[%d,%d](%d)"
        t.Cstruct.off t.Cstruct.len (Bigarray.Array1.dim t.Cstruct.buffer)
    ) t

let len = List.fold_left (fun acc c -> Cstruct.length c + acc) 0

let err fmt =
  let b = Buffer.create 20 in                         (* for thread safety. *)
  let ppf = Format.formatter_of_buffer b in
  let k ppf = Format.pp_print_flush ppf (); invalid_arg (Buffer.contents b) in
  Format.kfprintf k ppf fmt

let rec shift t x =
  if x = 0 then t else match t with
  | [] -> err "Cstructs.shift %a %d" pp_t t x
  | y :: ys ->
    let y' = Cstruct.length y in
    if y' > x
    then Cstruct.shift y x :: ys
    else shift ys (x - y')

let to_string t =
  let b = Buffer.create 20 in
  List.iter (fun x -> Buffer.add_string b @@ Cstruct.to_string x) t;
  Buffer.contents b

let sub t off len =
  let t' = shift t off in
  (* trim the length *)
  let rec trim acc ts remaining = match remaining, ts with
  | 0, _ -> List.rev acc
  | _, [] -> err "invalid bounds in Cstructs.sub %a off=%d len=%d" pp_t t off len
  | n, t :: ts ->
    let to_take = min (Cstruct.length t) n in
    (* either t is consumed and we only need ts, or t has data
       remaining in which case we're finished *)
    trim (Cstruct.sub t 0 to_take :: acc) ts (remaining - to_take)
  in
  trim [] t' len

let to_cstruct = function
| [ common_case ] -> common_case
| uncommon_case -> Cstruct.concat uncommon_case

(* Return a Cstruct.t representing (off, len) by either returning a reference
   or making a copy if the value is split across two fragments. Ideally this
   would return a string rather than a Cstruct.t for efficiency *)
let get f t off len =
  let t' = shift t off in
  match t' with
  | x :: xs ->
    (* Return a reference to the existing buffer *)
    if Cstruct.length x >= len
    then Cstruct.sub x 0 len
    else begin
      (* Copy into a fresh buffer *)
      let rec copy remaining frags =
        if Cstruct.length remaining > 0
        then match frags with
        | [] ->
          err "invalid bounds in Cstructs.%s %a off=%d len=%d" f pp_t t off len
        | x :: xs ->
          let to_copy = min (Cstruct.length x) (Cstruct.length remaining) in
          Cstruct.blit x 0 remaining 0 to_copy;
          (* either we've copied all of x, or we've filled the
             remaining buffer *)
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

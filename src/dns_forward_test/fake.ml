(*
 * Copyright (C) 2017 Docker Inc
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)

(* A fake Time and Clock module for testing the timing without having to actually
   wait. *)

let timeofday = ref 0L
let c = Lwt_condition.create ()

let advance nsecs =
  timeofday := Int64.add !timeofday nsecs;
  Lwt_condition.broadcast c ()

let reset () =
  timeofday := 0L;
  Lwt_condition.broadcast c ()

module Time = struct
  let sleep_ns n =
    let open Lwt.Infix in
    (* All sleeping is relative to the start of the program for now *)
    let now = 0L in
    let rec loop () =
      if !timeofday > Int64.add now n then Lwt.return_unit else (
        Lwt_condition.wait c >>= fun () ->
        loop ()
      ) in
    loop ()

end

module Clock = struct
  let elapsed_ns () = !timeofday
  let period_ns () = None
end

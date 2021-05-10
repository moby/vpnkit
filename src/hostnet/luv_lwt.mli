(* Both Lwt and Luv have their own schedulers which we run on separate Threads.

   This module contains helper functions to call from one scheduler/Thread context to
   the other.

   A typical example would be:


*)

val in_luv : (('a -> unit) -> unit) -> 'a Lwt.t
(** [in_luv f] is called from Lwt to run [f return] in the default Luv event loop.
    The function [return] may be used to return values to the Lwt caller.
    Example:

```
let do_some_io () : unit Lwt.t =
    Luv_lwt.in_luv (fun result ->
        (* Now we're in the Luv event loop *)
        Luv.Do.something _ begin function
        | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
        | Ok () -> return (Ok ())
        end
    )
```
    *)

(* To run in the Lwt main loop, use Lwt_preemptive.run_in_main *)

val in_luv_async : (unit -> unit) -> unit
(** [in_luv_async f] is called from Lwt to run [f ()] in the default Luv event loop.
    This is useful for cases where we don't need to wait for the results.
*)

val in_lwt_async : (unit -> unit) -> unit
(** [run_in_lwt f] is called from Luv to run [f ()] in the default Lwt event loop.
    Example:

```
let handle_connection client () =
    Lwt.async (fun () -> ...)

let accept_forever () =
    ...
    begin match Luv.Stream.accept ~server:fd ~client with
    | Error err -> ...
    | Ok () ->
        Luv_lwt.in_lwt_async (handle_connection client);
        accept_forever ()
    end
*)

val run : 'a Lwt.t -> 'a
(** [run t] evaluates [t] with the default Luv event loop. *)

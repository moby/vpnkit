(** The same error type is supported in Lwt > 2.5.2. Once that is released we
    can remove this shim. *)

type ('a, 'b) t = ('a, 'b) result Lwt.t

val return : 'a -> ('a, 'b) t

val fail : 'b -> ('a, 'b) t

module Infix: sig
  val (>>=): ('a, 'e) t -> ('a -> ('b, 'e) t) -> ('b, 'e) t
end

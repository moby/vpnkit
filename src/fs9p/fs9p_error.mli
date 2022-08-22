type t = Protocol_9p.Response.Err.t

val map_error : ('a, Vfs.Error.t) result -> ('a, t) result Lwt.t

val error : ?errno:int32 -> ('a, unit, string, ('b, t) result) format4 -> 'a

module Infix : sig
  val ( >>*= ) :
    ('a, t) result Lwt.t ->
    ('a -> ('b, t) result Lwt.t) ->
    ('b, t) result Lwt.t
end

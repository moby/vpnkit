type 'a t = ('a, [ `Msg of string ]) Hostnet_lwt_result.t

module Infix = Hostnet_lwt_result.Infix

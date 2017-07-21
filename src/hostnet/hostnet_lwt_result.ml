open Lwt.Infix

type ('a, 'b) t = ('a, 'b) result Lwt.t

let return x = Lwt.return (Ok x)
let fail   y = Lwt.return (Error y)

module Infix = struct
  let (>>=) m f = m >>= function
    | Error y -> Lwt.return (Error y)
    | Ok x -> f x
end

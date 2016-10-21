open Lwt.Infix

type ('a, 'b) t = ('a, 'b) Result.result Lwt.t

let return x = Lwt.return (Result.Ok x)
let fail   y = Lwt.return (Result.Error y)

module Infix = struct
  let (>>=) m f = m >>= function
    | Result.Error y -> Lwt.return (Result.Error y)
    | Result.Ok x -> f x
end

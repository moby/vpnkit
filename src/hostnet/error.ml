open Lwt.Infix

type 'a t = ('a, [ `Msg of string ]) Hostnet_lwt_result.t

module FromFlowError(Flow: V1_LWT.FLOW) = struct
  let (>>=) m f = m >>= function
    | `Eof -> Lwt.return (Result.Error (`Msg "Unexpected end of file"))
    | `Error e -> Lwt.return (Result.Error (`Msg (Flow.error_message e)))
    | `Ok x -> f x
end

let errorf fmt = Printf.ksprintf (fun s -> Lwt.return (Result.Error (`Msg s))) fmt

module Infix = Hostnet_lwt_result.Infix

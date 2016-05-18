include Sig.TCPIP

val connect: unit
  -> [ `Ok of t | `Error of [ `Msg of string ] ] Lwt.t

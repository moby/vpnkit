type 'a io = 'a Lwt.t

let sleep = Lwt_unix.sleep

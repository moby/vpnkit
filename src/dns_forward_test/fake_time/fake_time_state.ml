let timeofday = ref 0L
let c = Lwt_condition.create ()

let advance nsecs =
  timeofday := Int64.add !timeofday nsecs;
  Lwt_condition.broadcast c ()

let reset () =
  timeofday := 0L;
  Lwt_condition.broadcast c ()

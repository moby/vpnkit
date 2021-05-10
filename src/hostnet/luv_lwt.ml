module Result = struct
  include Result

  let get_ok = function Error _ -> invalid_arg "result is Error _" | Ok x -> x
end

module type Notification = sig
  type t
  (** Wake up and run code in a remote event loop *)

  val create : (unit -> unit) -> t

  val send : t -> unit
end

module Lwt_notification : Notification = struct
  type t = int
  (** Run code in an Lwt event loop *)

  let create cb = Lwt_unix.make_notification cb

  let send = Lwt_unix.send_notification
end

module Luv_notification : Notification = struct
  type t = [ `Async ] Luv.Handle.t
  (** Run code in the default Luv event loop *)

  let create cb = Luv.Async.init (fun _t -> cb ()) |> Result.get_ok

  let send t = Luv.Async.send t |> Result.get_ok
end

module type Remote_work_queue = sig
  type 'a t

  val make : ('a -> unit) -> 'a t

  val push : 'a t -> 'a -> unit

  val length : 'a t -> int
end

module Work_queue (N : Notification) : Remote_work_queue = struct
  type 'a t = {
    pending : 'a Queue.t;
    run : 'a -> unit;
    mutable n : N.t option;
    (* Note: if this is only used from a single-threaded Lwt or Luv context, then
       the mutex is unnecessary. The tests below use pthreads so require the mutex. *)
    m : Mutex.t;
  }
  (** A thread-safe queue of pending jobs which will be run in a remote event loop *)

  let flush t () =
    (* Called in the remote event loop to run pending jobs .*)
    Mutex.lock t.m;
    let to_run = Queue.copy t.pending in
    Queue.clear t.pending;
    Mutex.unlock t.m;
    Queue.iter t.run to_run

  let push t x =
    (* Called on an arbitrary thread to queue a remote job. *)
    Mutex.lock t.m;
    (* We only need to send a notification if the queue is currently empty, otherwise
       one has already been sent. *)
    let to_send = Queue.is_empty t.pending in
    Queue.push x t.pending;
    Mutex.unlock t.m;
    if to_send then N.send (Option.get t.n)

  let length t =
    Mutex.lock t.m;
    let result = Queue.length t.pending in
    Mutex.unlock t.m;
    result

  let make run =
    let t =
      {
        pending = Queue.create ();
        run;
        n = None;
        (* initialized below *)
        m = Mutex.create ();
      }
    in
    t.n <- Some (N.create (flush t));
    t
end

module Run_in_lwt = Work_queue (Lwt_notification)
module Run_in_luv = Work_queue (Luv_notification)

let to_luv_default_loop = Run_in_luv.make (fun f -> f ())

let to_lwt_default_loop = Run_in_lwt.make (fun f -> f ())

let in_lwt_async f = Run_in_lwt.push to_lwt_default_loop f

let in_luv_async = Run_in_luv.push to_luv_default_loop

let in_luv f =
  let t, u = Lwt.task () in
  let wakeup_later x = in_lwt_async (fun () -> Lwt.wakeup_later u x) in
  in_luv_async (fun () -> f wakeup_later);
  t

let run t =
  (* Hopefully it's ok to create the async handle in this thread, even though the
     main loop runs in another thread. *)
  let stop_default_loop =
    Luv.Async.init (fun h ->
        Luv.Loop.stop (Luv.Loop.default ());
        Luv.Handle.close h ignore)
    |> Result.get_ok
  in
  let luv = Thread.create (fun () -> ignore (Luv.Loop.run () : bool)) () in
  (* With the luv event loop running in the background, we can evaluate [t] *)
  let result = Lwt_main.run t in
  Luv.Async.send stop_default_loop |> Result.get_ok;
  Thread.join luv;
  result

let%test "wakeup one task from a luv callback" =
  let t, u = Lwt.task () in
  let luv = Thread.create (fun () -> in_lwt_async (Lwt.wakeup_later u)) () in
  Thread.join luv;
  Lwt_main.run t;
  true

let%test "wakeup lots of tasks from a luv callback" =
  let n = 1000 in
  let tasks = Array.init n (fun _ -> Lwt.task ()) |> Array.to_list in
  List.iteri
    (fun i (_, u) ->
      let (_ : Thread.t) =
        Thread.create
          (fun i ->
            (* Introduce jitter *)
            Thread.delay 0.5;
            in_lwt_async (fun () -> Lwt.wakeup_later u i))
          i
      in
      ())
    tasks;
  Lwt_main.run
    (let open Lwt.Infix in
    let ts = List.map fst tasks in
    Lwt_list.fold_left_s
      (fun acc b_t -> b_t >>= fun b -> Lwt.return (acc + b))
      0 ts)
  = n * (n - 1) / 2

let src =
  let src = Logs.Src.create "Luv" ~doc:"Host interface based on Luv" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let (_ : Thread.t) =
  Thread.create
    (fun () ->
      Log.info (fun f -> f "monitoring queue lengths");
      while true do
        Log.info (fun f ->
            f "run_in_luv queue length = %d"
              (Run_in_luv.length to_luv_default_loop));
        Log.info (fun f ->
            f "run_in_lwt queue length = %d"
              (Run_in_lwt.length to_lwt_default_loop));
        Thread.delay 2.
      done)
    ()

(* Test the protocol used by vpnkit-forwarder *)

let src =
  let src =
    Logs.Src.create "test-forwarder"
      ~doc:"Test the protocol used by the vpnkit-forwarder"
  in
  Logs.Src.set_level src (Some Logs.Info) ;
  src

module Log = (val Logs.src_log src : Logs.LOG)

open Forwarder.Frame

let inputs =
  [ ( "open_dedicated_connection"
    , { command= Open (Dedicated, `Tcp (Ipaddr.V4 Ipaddr.V4.localhost, 8080))
      ; id= 4l } )
  ; ( "open_multiplexed_connection"
    , { command= Open (Multiplexed, `Udp (Ipaddr.V6 Ipaddr.V6.localhost, 8080))
      ; id= 5l } )
  ; ( "open_multiplexed_unix_connection"
    , {command= Open (Multiplexed, `Unix "/tmp/foo"); id= 5l} )
  ; ("close", {command= Close; id= 6l})
  ; ("shutdown", {command= Shutdown; id= 7l})
  ; ("data", {command= Data 128l; id= 8l})
  ; ("window", {command= Window 8888888L; id= 9l}) ]

let output_dir = Filename.(concat (dirname Sys.argv.(0)) "test_inputs")

(* Regenerate test output files. This is only needed when changing the protocol and
   updating the tests. *)
let test_print name frame () =
  let buf = write frame (Cstruct.create (sizeof frame)) in
  let oc = open_out (Filename.concat output_dir (name ^ ".bin")) in
  output_string oc (Cstruct.to_string buf) ;
  close_out oc

let test_print_parse frame () =
  let buf = write frame (Cstruct.create (sizeof frame)) in
  let frame' = read buf in
  if frame <> frame' then (
    Printf.fprintf stderr "%s <> %s\n" (to_string frame) (to_string frame') ;
    assert false )

let test_parse name frame () =
  let ic = open_in (Filename.concat output_dir (name ^ ".bin")) in
  let b = Bytes.create 100 in
  (* more than big enough *)
  let n = input ic b 0 100 in
  close_in ic ;
  let buf = Cstruct.create n in
  Cstruct.blit_from_bytes b 0 buf 0 n ;
  let frame' = read buf in
  assert (frame = frame')

let packet_suite =
  List.map
    (fun (name, frame) ->
      ( name
      , [ (* "check that we can print", `Quick, test_print name frame; *)
          ( "check that we can parse what we print"
          , `Quick
          , test_print_parse frame )
        ; ( "check that we can parse files on disk"
          , `Quick
          , test_parse name frame ) ] ) )
    inputs

(* Test the multiplexing protocol *)

open Lwt.Infix

module Shared_memory = struct
  module Pipe = struct
    type t =
      { mutable bufs: Cstruct.t list
      ; mutable shutdown: bool
      ; c: unit Lwt_condition.t }

    let create () = {bufs= []; shutdown= false; c= Lwt_condition.create ()}

    let read t =
      match t.bufs with
      | [] -> if t.shutdown then `Eof else `Wait
      | buf :: bufs ->
          t.bufs <- bufs ;
          `Data buf

    let write t bufs =
      t.bufs <- t.bufs @ bufs ;
      Lwt_condition.signal t.c () ;
      Ok ()

    let shutdown_write t =
      t.shutdown <- true ;
      Lwt_condition.signal t.c ()
  end

  type t = {write: Pipe.t; read: Pipe.t; mutable closed: bool}

  let create () = {write= Pipe.create (); read= Pipe.create (); closed= false}

  let otherend t = {write= t.read; read= t.write; closed= false}

  let shutdown_write t =
    Pipe.shutdown_write t.write ;
    Lwt.return_unit

  let close t =
    t.closed <- true ;
    Lwt_condition.signal t.read.Pipe.c () ;
    Lwt.return_unit

  let read t =
    let rec wait () =
      if t.closed then Lwt.return (Ok `Eof)
      else
        match Pipe.read t.read with
        | `Eof -> Lwt.return (Ok `Eof)
        | `Data buf -> Lwt.return (Ok (`Data buf))
        | `Wait -> Lwt_condition.wait t.read.Pipe.c >>= fun () -> wait ()
    in
    wait ()

  let writev t bufs = Lwt.return (Pipe.write t.write bufs)

  let shutdown_read _chanel = Lwt.return_unit

  let write channel buf = writev channel [buf]

  type flow = t

  let pp_error ppf _ = Fmt.pf ppf "Unknown error"

  let pp_write_error ppf = function
    | `Closed -> Fmt.pf ppf "attempted to write to a closed flow"

  type error = []

  type write_error = Mirage_flow.write_error
end

(* Check it matches the signature *)
module Test : Mirage_flow_combinators.SHUTDOWNABLE = Shared_memory

module Mux = Forwarder.Multiplexer.Make (Shared_memory)

let test_connect_close () =
  Host.Main.run
    (let left_flow = Shared_memory.create () in
     let right_flow = Shared_memory.otherend left_flow in
     let left_mux =
       Mux.connect left_flow "left" (fun _channel _destination ->
           Lwt.fail_with "left side shouldn't get a connection" )
     in
     let _right_mux =
       Mux.connect right_flow "right" (fun channel destination ->
           Log.debug (fun f ->
               f "Got a connection to %s" (Destination.to_string destination)
           ) ;
           Mux.Channel.close channel )
     in
     Mux.Channel.connect left_mux (`Tcp (Ipaddr.V4 Ipaddr.V4.localhost, 8080))
     >>= fun channel -> Mux.Channel.close channel)

let test_close_close () =
  Host.Main.run
    (let left_flow = Shared_memory.create () in
     let right_flow = Shared_memory.otherend left_flow in
     let left_mux =
       Mux.connect left_flow "left" (fun _channel _destination ->
           Lwt.fail_with "left side shouldn't get a connection" )
     in
     let right_mux =
       Mux.connect right_flow "right" (fun channel destination ->
           Log.debug (fun f ->
               f "Got a connection to %s" (Destination.to_string destination)
           ) ;
           Mux.Channel.close channel )
     in
     Mux.Channel.connect left_mux (`Tcp (Ipaddr.V4 Ipaddr.V4.localhost, 8080))
     >>= fun channel ->
     Mux.Channel.close channel
     >>= fun () ->
     Mux.Channel.close channel
     >>= fun () ->
     if not (Mux.is_running left_mux)
     then failwith "left_mux has failed";
     if not (Mux.is_running right_mux)
     then failwith "right_mux has failed";
     Lwt.return_unit
     )

let test_close_shutdown () =
  Host.Main.run
    (let left_flow = Shared_memory.create () in
     let right_flow = Shared_memory.otherend left_flow in
     let left_mux =
       Mux.connect left_flow "left" (fun _channel _destination ->
           Lwt.fail_with "left side shouldn't get a connection" )
     in
     let right_mux =
       Mux.connect right_flow "right" (fun channel destination ->
           Log.debug (fun f ->
               f "Got a connection to %s" (Destination.to_string destination)
           ) ;
           Mux.Channel.close channel )
     in
     Mux.Channel.connect left_mux (`Tcp (Ipaddr.V4 Ipaddr.V4.localhost, 8080))
     >>= fun channel ->
     Mux.Channel.close channel
     >>= fun () ->
     Mux.Channel.shutdown_write channel
     >>= fun () ->
     if not (Mux.is_running left_mux)
     then failwith "left_mux has failed";
     if not (Mux.is_running right_mux)
     then failwith "right_mux has failed";
     Lwt.return_unit
     )

let send channel n =
  let sha = Sha256.init () in
  let rec loop n =
    if n = 0 then Lwt.return_unit
    else
      let send_buf = Cstruct.create 1024 in
      let this_time = min n (Cstruct.len send_buf) in
      let buf = Cstruct.sub send_buf 0 this_time in
      for i = 0 to Cstruct.len buf - 1 do
        Cstruct.set_uint8 buf i (Random.int 255)
      done ;
      Sha256.update_string sha (Cstruct.to_string buf) ;
      Mux.Channel.write channel buf
      >>= function
      | Error _ -> Lwt.fail_with (Printf.sprintf "send %d got error" n)
      | Ok () -> loop (n - this_time)
  in
  loop n >>= fun () -> Lwt.return Sha256.(to_hex @@ finalize sha)

let count_recv channel =
  let sha = Sha256.init () in
  let rec loop n =
    Mux.Channel.read channel
    >>= function
    | Error _ -> Lwt.fail_with (Printf.sprintf "recv got error after %d" n)
    | Ok `Eof -> Lwt.return n
    | Ok (`Data buf) ->
        Sha256.update_string sha (Cstruct.to_string buf) ;
        loop (Cstruct.len buf + n)
  in
  loop 0 >>= fun n -> Lwt.return (n, Sha256.(to_hex @@ finalize sha))

type metadata = {written: int; written_sha: string; read: int; read_sha: string}

let compare_metadata left right =
  if left.written <> right.read then
    failwith
      (Printf.sprintf "Left wrote %d but right only read %d" left.written
         right.read) ;
  if right.read_sha <> left.written_sha then
    failwith
      (Printf.sprintf "Left has written sha %s but write has read %s"
         left.written_sha right.read_sha) ;
  if left.read_sha <> right.written_sha then
    failwith
      (Printf.sprintf "Right has written sha %s but left has read %s"
         right.written_sha left.read_sha) ;
  if right.written <> left.read then
    failwith
      (Printf.sprintf "Right wrote %d but left only read %d" right.written
         left.read)

let read_and_write channel to_write =
  let read = count_recv channel in
  send channel to_write
  >>= fun written_sha ->
  Mux.Channel.shutdown_write channel
  >>= fun () ->
  read
  >>= fun (num_read, sha) ->
  Lwt.return {written= to_write; written_sha; read= num_read; read_sha= sha}

let port_of = function
  | `Tcp (_, port) -> port
  | `Udp (_, port) -> port
  | `Unix _ -> failwith "Unix destinations do not have a port"

let test_read_write to_write_left to_write_right =
  let right_metadata = Hashtbl.create 7 in
  Host.Main.run
    (let left_flow = Shared_memory.create () in
     let right_flow = Shared_memory.otherend left_flow in
     let left_mux =
       Mux.connect left_flow "left" (fun _channel _destination ->
           Lwt.fail_with "left side shouldn't get a connection" )
     in
     let _right_mux =
       Mux.connect right_flow "right" (fun channel destination ->
           Log.debug (fun f ->
               f "Got a connection to %s" (Destination.to_string destination)
           ) ;
           read_and_write channel to_write_right
           >>= fun metadata ->
           Hashtbl.replace right_metadata (port_of destination) metadata ;
           Mux.Channel.close channel )
     in
     let port = 8080 in
     Mux.Channel.connect left_mux (`Tcp (Ipaddr.V4 Ipaddr.V4.localhost, port))
     >>= fun channel ->
     read_and_write channel to_write_left
     >>= fun metadata ->
     compare_metadata metadata (Hashtbl.find right_metadata port) ;
     Mux.Channel.close channel)

let interesting_sizes =
  [ 0
  ; 1
  ; 4
  ; 4095
  ; 4096
  ; 4097
  ; 4098
  ; 4099
  ; 5000
  ; 5001
  ; 5002
  ; 1048575
  ; 1048576
  ; 1048577 ]

let rec cross xs ys =
  match xs with
  | [] -> []
  | x :: xs -> List.map (fun y -> (x, y)) ys @ cross xs ys

let test_buffering =
  [ ( "buffering"
    , List.map
        (fun (x, y) ->
          ( Printf.sprintf "write %d, write %d" x y
          , `Quick
          , fun () -> test_read_write x y ) )
        (cross interesting_sizes interesting_sizes) ) ]

let stress_multiplexer () =
  let right_metadata = Hashtbl.create 7 in
  Host.Main.run
    (let left_flow = Shared_memory.create () in
     let right_flow = Shared_memory.otherend left_flow in
     let left_mux =
       Mux.connect left_flow "left" (fun _channel _destination ->
           Lwt.fail_with "left side shouldn't get a connection" )
     in
     let _right_mux =
       Mux.connect right_flow "right" (fun channel destination ->
           Log.debug (fun f ->
               f "Got a connection to %s" (Destination.to_string destination)
           ) ;
           read_and_write channel (Random.int 8192)
           >>= fun metadata ->
           Hashtbl.replace right_metadata (port_of destination) metadata ;
           Mux.Channel.close channel )
     in
     let rec mkints a b = if a = b then [] else a :: mkints (a + 1) b in
     (* 2000 concurrent connections 10 times in a row *)
     let rec loop n =
       if n = 10 then Lwt.return_unit
       else
         (let ports = mkints 1 2000 in
          let threads =
            List.map
              (fun port ->
                Mux.Channel.connect left_mux
                  (`Tcp (Ipaddr.V4 Ipaddr.V4.localhost, port))
                >>= fun channel ->
                read_and_write channel (Random.int 8192)
                >>= fun metadata ->
                compare_metadata metadata (Hashtbl.find right_metadata port) ;
                Mux.Channel.close channel )
              ports
          in
          Lwt.join threads)
         >>= fun () -> loop (n + 1)
     in
     loop 0)

let mux_suite =
  [ ( "multiplexer"
    , [ ( "check that the multiplexer can connect and disconnect"
        , `Quick
        , test_connect_close )
      ; ( "check that double-close doesn't break the connection"
        , `Quick
        , test_close_close )
      ; ( "check that shutdown after close doesn't break the connection"
        , `Quick
        , test_close_shutdown )
      ; ( "check that the multiplexer can handle concurrent connections"
        , `Quick
        , stress_multiplexer ) ] ) ]

let suite = packet_suite @ mux_suite @ test_buffering

let src =
  let src = Logs.Src.create "usernet" ~doc:"Mirage TCP/IP <-> socket proxy" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Port = struct
  type t = int32

  let of_string x =
    try
      Result.Ok (Int32.of_string ("0x" ^ x))
    with
    | _ -> Result.Error (`Msg (Printf.sprintf "vchan port is not a hexadecimal int32: '%s'" x))
  let to_string x = Printf.sprintf "%08lx" x

end

let connect port =
  Log.err (fun f -> f "Hyper-V socket connect() not yet implemented");
  failwith "Hyper-V socket connect() not yet implemented"

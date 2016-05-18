let vsock_path = ref "/var/tmp/com.docker.vsock/connect"

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
  Osx_hyperkit.Vsock.connect ~path:!vsock_path ~port ()

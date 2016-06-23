open Lwt
open Vmnet

let src =
  let src = Logs.Src.create "vmnet" ~doc:"vmnet" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let error_of_failure f = Lwt.catch f (fun e -> Lwt.return (`Error (`Msg (Printexc.to_string e))))

type t = {
  fd: Lwt_unix.file_descr;
}


module Infix = struct
  let ( >>= ) m f = m >>= function
    | `Ok x -> f x
    | `Error x -> Lwt.return (`Error x)
end

let of_fd fd =
  let buf = Cstruct.create Init.sizeof in
  let (_: Cstruct.t) = Init.marshal Init.default buf in
  error_of_failure
    (fun () ->
       Lwt_cstruct.(complete (write fd) buf)
       >>= fun () ->
       Lwt_cstruct.(complete (read fd) buf)
       >>= fun () ->
       let open Infix in
       Lwt.return (Init.unmarshal buf)
       >>= fun (init, _) ->
       Log.info (fun f -> f "Client.negotiate: received %s" (Init.to_string init));
       Lwt.return (`Ok { fd })
    )

let bind_ipv4 t (ipv4, port, stream) =
  let buf = Cstruct.create Command.sizeof in
  let (_: Cstruct.t) = Command.marshal (Command.Bind_ipv4(ipv4, port, stream)) buf in
  Lwt_cstruct.(complete (write t.fd) buf)
  >>= fun () ->
  let result = String.make 8 '\000' in
  Lwt_unix.set_blocking ~set_flags:true t.fd true;
  let n, _, fd = Fd_send_recv.recv_fd (Lwt_unix.unix_file_descr t.fd) result 0 8 [] in
  if n <> 8 then Lwt.return (`Error (`Msg (Printf.sprintf "Message only contained %d bytes" n))) else begin
    let buf = Cstruct.create 8 in
    Cstruct.blit_from_string result 0 buf 0 8;
    Log.debug (fun f ->
        let b = Buffer.create 16 in
        Cstruct.hexdump_to_buffer b buf;
        f "received result bytes: %s which is %s" (String.escaped result) (Buffer.contents b)
      );
    match Cstruct.LE.get_uint64 buf 0 with
    | 0L -> Lwt.return (`Ok fd)
    | n ->
      Unix.close fd;
      begin match Errno.of_code ~host:Errno_unix.host (Int64.to_int n) with
        | x :: _ ->
          Lwt.return (`Error (`Msg ("Failed to bind: " ^ (Errno.to_string x))))
        | [] ->
          Lwt.return (`Error (`Msg ("Failed to bind: unrecognised errno: " ^ (Int64.to_string n))))
      end

  end

(* A debug tool, intended to check the I/O subsystem is working correctly. *)

open Lwt.Infix

let lookup host =
  Host.Dns.getaddrinfo host `INET
  >>= function
  | [] ->
    Lwt.fail_with (Printf.sprintf "unable to lookup %s" host)
  | Ipaddr.V6 _ :: _ ->
    Lwt.fail_with "IPv6 not currently supported."
  | Ipaddr.V4 ipv4 :: _ ->
    Lwt.return (Ipaddr.V4 ipv4)

module Client(FLOW: Mirage_flow.S) = struct
  module C = Mirage_channel.Make(FLOW)
  let get flow host path =
    let request = "GET " ^ path ^ " HTTP/1.0\r\nHost: " ^ host ^ "\r\nConnection: close\r\n\r\n" in
    let c = C.create flow in
    Printf.printf "writing\n%s\n" request;
    C.write_string c request 0 (String.length request);
    C.flush c
    >>= function
    | Error e ->
      Printf.printf "error sending request: %s\n" (Fmt.str "%a" C.pp_write_error e);
      Lwt.return_unit
    | Ok () ->
      let rec loop () =
        C.read_some c >>= function
        | Ok `Eof        -> Lwt.return_unit
        | Error e        ->
          Printf.printf "error reading response: %s\n" (Fmt.str "%a" C.pp_error e);
          Lwt.return_unit
        | Ok (`Data buf) ->
          print_string (Cstruct.to_string buf);
          loop () in
      loop ()
end

let curl _verbose urls =
  let module HTTP = Client(Host.Sockets.Stream.Tcp) in
  let fetch host port path =
    let path = if path = "" then "/" else path in
    lookup host
    >>= fun ipv4 ->
    Printf.printf "connecting to %s:%d\n" (Ipaddr.to_string ipv4) port;
    Host.Sockets.Stream.Tcp.connect (ipv4, port)
    >>= function
    | Error (`Msg m) ->
      Printf.printf "unable to connect: %s\n" m;
      Lwt.return_unit
    | Ok socket ->
      Printf.printf "connected\n";
      Lwt.finalize
        (fun () ->
          HTTP.get socket host path
        ) (fun () -> Host.Sockets.Stream.Tcp.close socket) in
  try
    Host.Main.run begin
      Lwt_list.iter_s (fun url ->
        let uri = Uri.of_string url in
        if Uri.scheme uri <> Some "http" then begin
          Printf.printf "only http:// URLs are currently supported by this debug tool\n";
          Lwt.return_unit
        end else begin
          Printf.printf "trying URL %s\n" url;
          let path = Uri.path uri in
          match Uri.host uri, Uri.port uri with
          | Some host, Some port ->
            fetch host port path
          | Some host, None ->
            fetch host 80 path
          | _, _ ->
            Printf.printf "unable to parse host and port from URL\n";
            Lwt.return_unit
          end
      ) urls
    end
  with e ->
    Printf.printf "Host.Main.run caught exception %s: %s\n" (Printexc.to_string e) (Printexc.get_backtrace ())
(*
 * Copyright (C) 2016 David Scott <dave.scott@docker.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)
let install () =
  let home = try Unix.getenv "HOME" with Not_found -> failwith "No $HOME environment variable defined" in
  let (/) = Filename.concat in
  let localtime = Unix.localtime @@ Unix.gettimeofday () in
  let dir = Printf.sprintf "%04d-%02d-%02d"
    (localtime.Unix.tm_year + 1900)
    (localtime.Unix.tm_mon + 1)
    localtime.Unix.tm_mday in
  let log_root = [ "Library"; "Containers"; "com.docker.docker"; "Data"; "logs"; dir ] in
  (* mkdir -p *)
  ignore @@ List.fold_left (fun cwd dir ->
    let path = cwd / dir in
    ( try Unix.mkdir (home / path) 0o0755 with | Unix.Unix_error(Unix.EEXIST, _, _) -> () );
    path
  ) "" log_root;
  let ident = Filename.basename Sys.executable_name in
  let file = List.fold_left (/) home (log_root @ [ ident ^ ".log" ]) in
  let fd = Unix.openfile file [ Unix.O_WRONLY; Unix.O_APPEND; Unix.O_CREAT ] 0o0644 in
  let client = Asl.Client.create ~ident ~facility:"Daemon" () in
  let msg_fmt = "$((Time)(ISO8601.6)) $((Level)(str)) - $Message" in
  let time_fmt = "$((Time)(utc))" in
  if not (Asl.Client.add_output_file client fd msg_fmt time_fmt `Debug) then begin
    failwith (Printf.sprintf "Failed to start logging to %s" file)
  end;
  Logs.set_reporter (Log_asl.reporter ~client ())

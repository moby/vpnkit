#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"

open Topkg
open Result

let distrib = Pkg.distrib ~files_to_watermark:(fun () -> Ok [ "src/main.ml" ]) ()

let () =
  Pkg.describe ~distrib ~change_logs:[] ~metas:[] "com.docker.slirp" @@ fun c ->
  Ok [ Pkg.bin "src/main" ~dst:"com.docker.slirp" ]

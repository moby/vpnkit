#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"

open Topkg
open Result

let () =
  Pkg.describe ~change_logs:[] ~metas:[] "com.docker.slirp" @@ fun c ->
  Ok [ Pkg.bin "src/main" ~dst:"com.docker.slirp" ]

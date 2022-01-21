#!/usr/bin/env sh

set -e

cd "${APPVEYOR_BUILD_FOLDER}"

opam exec -- dune build COMMIT
opam exec -- dune build licenses.json
opam exec -- dune build vpnkit.exe
opam exec -- dune test

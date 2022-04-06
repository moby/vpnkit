#!/usr/bin/env sh

set -e

cd "${APPVEYOR_BUILD_FOLDER}"

rm -f _build/default/COMMIT
opam exec -- dune build COMMIT
opam exec -- dune build licenses.json
opam exec -- dune build vpnkit.exe
opam exec -- dune test

#!/usr/bin/env sh

set -eu

cd "${APPVEYOR_BUILD_FOLDER}"

export REPO_ROOT=$(git rev-parse --show-toplevel)
export OPAM_REPO=$(cygpath.exe -w "${REPO_ROOT}/repo/win32")
export OPAMROOT=$(cygpath.exe -w "${REPO_ROOT}/_build/opam")
# NOTE: this is where all the binaries will end up, e.g. `oasis`
# This must be on the end of the path or else Windows will try to
# execute the opam metadata file in vpnkit!
export PATH="${PATH}:${BINDIR}"

make
make test
make artefacts
make OSS-LICENSES
make COMMIT

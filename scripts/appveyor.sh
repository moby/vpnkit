#!/usr/bin/env sh

set -eu

### From ocaml-ci-scripts

# default setttings
SWITCH='4.03.0+mingw64c'
OPAM_URL='https://dl.dropboxusercontent.com/s/b2q2vjau7if1c1b/opam64.tar.xz'
OPAM_ARCH=opam64

if [ "$PROCESSOR_ARCHITECTURE" != "AMD64" ] && \
       [ "$PROCESSOR_ARCHITEW6432" != "AMD64" ]; then
    OPAM_URL='https://dl.dropboxusercontent.com/s/eo4igttab8ipyle/opam32.tar.xz'
    OPAM_ARCH=opam32
fi

export OPAM_LINT="false"
export OPAMYES=1

curl -fsSL -o "${OPAM_ARCH}.tar.xz" "${OPAM_URL}"
tar -xf "${OPAM_ARCH}.tar.xz"
"${OPAM_ARCH}/install.sh"

PATH="/usr/x86_64-w64-mingw32/sys-root/mingw/bin:${PATH}"
export PATH

### Custom

cd "${APPVEYOR_BUILD_FOLDER}"

export REPO_ROOT=$(git rev-parse --show-toplevel)
export OPAM_REPO=$(cygpath.exe -w "${REPO_ROOT}/repo/win32")
export OPAMROOT=$(cygpath.exe -w "${REPO_ROOT}/_build/opam")
# NOTE: this is where all the binaries will end up, e.g. `oasis`
# This must be on the end of the path or else Windows will try to
# execute the opam metadata file in vpnkit!
export BINDIR='C:\projects\vpnkit'
export PATH="${PATH}:${BINDIR}"

${APPVEYOR_BUILD_FOLDER}/scripts/common.sh

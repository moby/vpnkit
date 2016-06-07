#!/usr/bin/env sh

### From ocaml-ci-scripts

# default setttings
SWITCH='4.02.3+mingw64c'
OPAM_URL='https://dl.dropboxusercontent.com/s/b2q2vjau7if1c1b/opam64.tar.xz'
OPAM_ARCH=opam64

if [ "$PROCESSOR_ARCHITECTURE" != "AMD64" ] && \
       [ "$PROCESSOR_ARCHITEW6432" != "AMD64" ]; then
    OPAM_URL='https://dl.dropboxusercontent.com/s/eo4igttab8ipyle/opam32.tar.xz'
    OPAM_ARCH=opam32
fi

# default setttings
SWITCH='4.02.3+mingw64c'
OPAM_URL='https://dl.dropboxusercontent.com/s/b2q2vjau7if1c1b/opam64.tar.xz'

export OPAM_LINT="false"
export CYGWIN='winsymlinks:native'
export OPAMYES=1

curl -fsSL -o "${OPAM_ARCH}.tar.xz" "${OPAM_URL}"
tar -xf "${OPAM_ARCH}.tar.xz"
"${OPAM_ARCH}/install.sh"

### Custom

cd "${APPVEYOR_BUILD_FOLDER}"

make depends
make
make OSS-LICENSES

#!/usr/bin/env sh
set -ex

# Common setup for both Appveyor and Circle CI

REPO_ROOT=$(git rev-parse --show-toplevel)

if [ -z "${OPAMROOT}" ]; then
  OPAMROOT=${REPO_ROOT}/_build/opam
fi

export OPAMROOT
export OPAMYES=1
export OPAMCOLORS=1

opam init -v -n --comp="${OPAM_COMP}" --switch="${OPAM_COMP}" local "${OPAM_REPO}"
echo opam configuration is:
opam config env
eval $(opam config env)

export PATH="${OPAMROOT}/${OPAM_COMP}/bin:${PATH}"

opam install depext -y -v
opam install depext-cygwinports -y || true

OPAMBUILDTEST=1 opam depext -u slirp
# Don't run all the unit tests of all upstream packages in the universe
# for speed. As a special exception we will run the tests for tcpip
OPAMVERBOSE=1 opam install --deps-only tcpip -y
OPAMVERBOSE=1 opam install tcpip -t

opam install $(ls -1 ${OPAM_REPO}/packages/upstream) -y
OPAMVERBOSE=1 opam install --deps-only slirp -y

OPAMVERBOSE=1 make
OPAMVERBOSE=1 make test
OPAMVERBOSE=1 make artefacts
OPAMVERBOSE=1 make OSS-LICENSES
OPAMVERBOSE=1 make COMMIT

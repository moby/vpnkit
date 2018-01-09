#!/usr/bin/env sh
set -ex
# Common setup for both Appveyor and Circle CI

REPO_ROOT=$(git rev-parse --show-toplevel)

${REPO_ROOT}/scripts/depends.sh

if [ -z "${OPAMROOT}" ]; then
  OPAMROOT=${REPO_ROOT}/_build/opam
fi

export OPAMROOT
export OPAMYES=1
export OPAMCOLORS=1

OPAMVERBOSE=1 make
OPAMVERBOSE=1 make test
OPAMVERBOSE=1 make artefacts
OPAMVERBOSE=1 make OSS-LICENSES
OPAMVERBOSE=1 make COMMIT

#!/bin/sh
set -ex

eval `opam config env`

opam pin add -k git osx-hyperkit.dev . -n
opam install osx-hyperkit

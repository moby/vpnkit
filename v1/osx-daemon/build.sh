#!/bin/sh
set -ex

eval `opam config env`

opam pin add -k git osx-daemon.dev . -n
opam install osx-daemon

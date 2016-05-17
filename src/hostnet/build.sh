#!/bin/sh
set -ex

eval `opam config env`

opam pin add -k git hostnet.dev . -n
opam install hostnet

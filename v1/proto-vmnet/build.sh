#!/bin/sh
set -ex

eval `opam config env`

opam pin add -k git proto-vmnet.dev . -n
opam install proto-vmnet

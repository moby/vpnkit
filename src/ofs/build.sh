#!/bin/sh
set -ex

eval `opam config env`

opam pin add -k git ofs.dev . -n
opam install ofs

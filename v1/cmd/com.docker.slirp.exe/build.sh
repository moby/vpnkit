#!/bin/sh -ex

eval `opam config env`
oasis setup
make

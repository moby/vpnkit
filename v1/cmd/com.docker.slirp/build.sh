#!/bin/sh -ex

eval `opam config env`
oasis setup
make
# bundler dylib dependencies
mkdir -p _build/root/Contents/MacOS
mv main.native com.docker.slirp
cp com.docker.slirp _build/root/Contents/MacOS/com.docker.slirp
dylibbundler -od -b \
  -x _build/root/Contents/MacOS/com.docker.slirp \
  -d _build/root/Contents/Resources/lib \
  -p @executable_path/../Resources/lib

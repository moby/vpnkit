#!/bin/sh -ex

# use the default pkg-config directory for the .pc
PKG_CONFIG_PATH=$(pkg-config --variable pc_path pkg-config | cut -f 1 -d ":")

# put the library and headers in /usr/local
PREFIX=/usr/local

LIBDIR="$PREFIX/lib/"
INCLUDEDIR="$PREFIX/include/libuv"

mkdir -p "$LIBDIR"
ranlib libuv.a
cp libuv.a "$LIBDIR"
mkdir -p "$INCLUDEDIR"
cp include/*.h "$INCLUDEDIR"
mkdir -p "$PKG_CONFIG_PATH"
cp libuv.pc "$PKG_CONFIG_PATH"

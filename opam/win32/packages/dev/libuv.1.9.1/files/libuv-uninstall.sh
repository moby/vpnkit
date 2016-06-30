#!/bin/sh -ex

# use the default pkg-config directory for the .pc
PKG_CONFIG_PATH=$(pkg-config --variable pc_path pkg-config | cut -f 1 -d ":")

# put the library and headers in /usr/local
PREFIX=/usr/local

LIBDIR="$PREFIX/lib/"
INCLUDEDIR="$PREFIX/include/libuv"

rm -f "$LIBDIR/libuv.a"
rm -f "$INCLUDEDIR/*.h"
rm -f "$PKG_CONFIG_PATH/libuv.pc"

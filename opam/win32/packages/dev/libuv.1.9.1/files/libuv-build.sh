#!/bin/sh -ex
export AR=/usr/bin/x86_64-w64-mingw32-ar.exe
export CFLAGS="-march=x86-64 -mtune=generic -mms-bitfields"
make -f Makefile.mingw


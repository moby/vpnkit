#!/usr/bin/env dash

cc=$(ocamlc -config | awk '/^bytecomp_c_compiler/ {for(i=2;i<=NF;i++) printf "%s ", $i}')
$cc -c $CFLAGS test.c

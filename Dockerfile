FROM ocaml/opam:alpine-ocaml-5.3 AS build
RUN opam update
# Static zstd is needed because OCaml 5.x compiler-libs link against zstd and
# the binary is statically linked (see src/bin/config/discover.ml).
RUN sudo apk add --no-cache zstd-static

ADD . /home/opam/vpnkit
RUN opam pin add vpnkit /home/opam/vpnkit --kind=path -n
RUN opam install vpnkit -y

FROM scratch AS binary
COPY --from=build /home/opam/.opam/5.3/bin/vpnkit /vpnkit

FROM alpine:latest
COPY --from=binary /vpnkit /vpnkit

FROM ocaml/opam:alpine-3.15-ocaml-4.14 as build
RUN opam update

ADD . /home/opam/vpnkit
RUN opam pin add vpnkit /home/opam/vpnkit --kind=path -n
RUN opam depext vpnkit -y

RUN opam install vpnkit -y

FROM scratch AS binary
COPY --from=build /home/opam/.opam/4.14/bin/vpnkit /vpnkit

FROM alpine:latest
COPY --from=binary /vpnkit /vpnkit

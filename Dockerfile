FROM ocaml/opam:alpine-ocaml-5.3 AS build
RUN opam-2.2 update

ADD . /home/opam/vpnkit
RUN opam-2.2 pin add vpnkit file:///home/opam/vpnkit -n

RUN opam-2.2 install vpnkit -y

FROM scratch AS binary
COPY --from=build /home/opam/.opam/5.3/bin/vpnkit /vpnkit

FROM alpine:latest
COPY --from=binary /vpnkit /vpnkit

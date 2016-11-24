FROM ocaml/opam:alpine
ADD . /home/opam/src
# Latest packages plus some overrides are in this repo:
RUN opam remote add vpnkit /home/opam/src/repo/darwin
RUN opam pin add -y -n vpnkit /home/opam/src
RUN opam depext vpnkit -y
RUN opam install --deps-only vpnkit -y
RUN opam pin remove vpnkit
WORKDIR /home/opam/src

FROM ocaml/opam2:alpine
ADD . /home/opam/src
# Latest packages plus some overrides are in this repo:
RUN opam remote add vpnkit /home/opam/src/repo/darwin
RUN opam pin add -y -n vpnkit /home/opam/src
RUN opam depext vpnkit -y
RUN opam pin add -y -n tcpip https://github.com/djs55/mirage-tcpip.git#vpnkit-20180607
RUN opam install --deps-only vpnkit -y
RUN opam pin remove vpnkit
WORKDIR /home/opam/src

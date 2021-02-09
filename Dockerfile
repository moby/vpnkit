FROM ocaml/opam2:alpine-3.10-ocaml-4.07 as build
ADD . /home/opam/src
# Latest packages plus some overrides are in this repo:
RUN opam remote add vpnkit /home/opam/src/repo/darwin
RUN opam pin add -y -n vpnkit /home/opam/src
RUN opam depext vpnkit -y
RUN opam pin add -y -n tcpip https://github.com/djs55/mirage-tcpip.git#vpnkit-20180607
# Work around uri build failure
ENV OPAMJOBS=1
RUN opam install re.1.9.0
RUN opam install uri.2.2.1
RUN opam install --deps-only vpnkit -y
RUN opam pin remove vpnkit
WORKDIR /home/opam/src
RUN opam exec -- sudo dune build src/bin/main.exe

FROM scratch
COPY --from=build /home/opam/src/_build/default/src/bin/main.exe /vpnkit

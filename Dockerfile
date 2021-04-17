FROM ocaml/opam2:alpine-3.10-ocaml-4.10 as build

RUN opam pin add fd-send-recv.2.0.1 https://github.com/xapi-project/ocaml-fd-send-recv/archive/v2.0.1.tar.gz
# A small fork of the tcpip stack
RUN opam pin add tcpip.3.3.0 "https://github.com/djs55/mirage-tcpip.git#vpnkit-20210417" -n
# This has been released in version 2 but with some other incompatible changes
RUN opam pin add hvsock.1.0.1 "git://github.com/djs55/ocaml-hvsock.git#relative-paths" -n

ADD . /home/opam/src
RUN opam pin add -y -n vpnkit /home/opam/src
RUN opam depext vpnkit -y

# Work around uri build failure (maybe remove when we update jbuilder/dune)
ENV OPAMJOBS=1
RUN opam install re.1.9.0
RUN opam install uri.2.2.1
ENV OPAMJOBS=8

RUN opam install --deps-only vpnkit -y

WORKDIR /home/opam/src
RUN opam exec -- sudo dune build --profile release

FROM alpine:latest
COPY --from=build /home/opam/src/_build/default/src/bin/main.exe /vpnkit

FROM ocaml/opam:alpine-3.13-ocaml-4.12 as build

# Not in the opam-repository metadata in the image. Remove after the image is updated:
RUN opam pin add lwt.5.4.0 https://github.com/ocsigen/lwt/archive/5.4.0.zip -n
RUN opam pin add fd-send-recv.2.0.1 https://github.com/xapi-project/ocaml-fd-send-recv/archive/v2.0.1.tar.gz -n
RUN opam pin add hvsock.2.0.0 https://github.com/mirage/ocaml-hvsock/archive/2.0.0.tar.gz -n

# Can be removed after we upgrade tcpip
RUN opam pin configurator --dev-repo -n
# Fix for Apple Silicon codesign issue
RUN opam pin add omake "https://github.com/ocaml-omake/omake.git#gerd/disable-parallel-bootstrap" -n
# Fix for OCaml 4.12 build
RUN opam pin add uwt "https://github.com/fdopen/uwt.git#c43349bf3689181756feb341e3896d4a0a695523" -n
RUN sudo apk add libtool autoconf automake # missing depexts
# A small fork of the tcpip stack
RUN opam pin add tcpip.3.3.0 "https://github.com/djs55/mirage-tcpip.git#vpnkit-20210417" -n

ADD . /home/opam/vpnkit
RUN opam pin add vpnkit /home/opam/vpnkit -n
RUN opam depext vpnkit -y

# Work around uri build failure (maybe remove when we update jbuilder/dune)
ENV OPAMJOBS=1
RUN opam install re.1.9.0
RUN opam install uri.2.2.1
ENV OPAMJOBS=8

RUN opam install --deps-only vpnkit -y

WORKDIR /home/opam/vpnkit
RUN opam exec -- sudo dune build --profile release

FROM alpine:latest
COPY --from=build /home/opam/vpnkit/_build/default/src/bin/main.exe /vpnkit

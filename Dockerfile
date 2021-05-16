FROM ocaml/opam:alpine-3.13-ocaml-4.12 as build
RUN opam update

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
# While waiting for the release:
RUN opam pin add hvsock.3.0.0 "https://github.com/djs55/ocaml-hvsock.git#release.3.0.0" -n
RUN opam pin add protocol-9p.2.0.1 "https://github.com/djs55/ocaml-9p.git" -n
RUN opam pin add protocol-9p-unix.2.0.1 "https://github.com/djs55/ocaml-9p.git" -n

RUN sudo apk add libtool autoconf automake # missing depexts

ADD . /home/opam/vpnkit
RUN opam pin add vpnkit /home/opam/vpnkit -n
RUN opam depext vpnkit -y

RUN opam install vpnkit -y

FROM alpine:latest
COPY --from=build /home/opam/.opam/4.12/bin/vpnkit /vpnkit

FROM ocaml/opam:alpine-3.15-ocaml-4.14 as build
RUN opam remote

# Fix for Apple Silicon codesign issue
RUN opam pin add omake "https://github.com/ocaml-omake/omake.git#0e4aef74dfe005b4e880cd13c08f7c57fa4a030b" -n
# Fix for OCaml 4.12 build
RUN opam pin add uwt "https://github.com/fdopen/uwt.git#c43349bf3689181756feb341e3896d4a0a695523" -n

RUN sudo apk add libtool autoconf automake # missing depexts

ADD . /home/opam/vpnkit
RUN opam pin add vpnkit /home/opam/vpnkit -n
RUN opam depext vpnkit -y

RUN opam install vpnkit -y

FROM alpine:latest
COPY --from=build /home/opam/.opam/4.14/bin/vpnkit /vpnkit

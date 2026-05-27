FROM ocaml/opam:alpine-3.23-ocaml-4.14 AS build
RUN sudo ln -sf /usr/bin/opam-2.5 /usr/bin/opam && \
  opam init --reinit -ni
RUN opam repo add archive-without-constraint git+https://github.com/tarides/moby-vpnkit-opam-repository-archive#remove-dune-upper-constraint --all

ADD . /home/opam/vpnkit
RUN opam pin add vpnkit /home/opam/vpnkit --kind=path -n
RUN opam install vpnkit -y

FROM alpine:latest
COPY --from=build /home/opam/.opam/4.14/bin/vpnkit /vpnkit

FROM ocaml/opam:alpine
RUN sudo apk add --update ncurses
ADD . /home/opam/src
RUN sudo chown -R opam /home/opam/src/
RUN opam repo add dev /home/opam/src/repo
RUN opam pin add -y -n proto-vmnet /home/opam/src/v1/proto-vmnet
RUN opam pin add -y -n ofs /home/opam/src/v1/ofs
RUN opam pin add -y -n hostnet /home/opam/src/v1/hostnet
RUN opam pin add -y -n osx-daemon /home/opam/src/v1/osx-daemon
RUN opam depext -u proto-vmnet
RUN opam depext -u ofs
RUN opam depext -u hostnet
RUN opam install -j 2 -v -y proto-vmnet
RUN opam install -j 2 -v -y ofs
RUN opam install -j 2 -v -y hostnet

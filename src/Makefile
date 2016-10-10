build: bin/depends.ml setup.data
	ocaml setup.ml -build

setup.data: setup.ml
	ocaml setup.ml -configure

setup.ml: _oasis
	oasis setup

bin/depends.ml: bin/depends.ml.in
	opam config subst bin/depends.ml
	cp bin/depends.ml bin/depends.tmp
	sed -e 's/%%VERSION%%/$(shell git rev-parse HEAD)/g' bin/depends.tmp > bin/depends.ml
	cp bin/depends.ml bin/depends.tmp
	sed -e 's/%%HOSTNET_PINNED%%/$(shell opam info hostnet -f pinned)/g' bin/depends.tmp > bin/depends.ml
	cp bin/depends.ml bin/depends.tmp
	sed -e 's/%%HVSOCK_PINNED%%/$(shell opam info hvsock -f pinned)/g' bin/depends.tmp > bin/depends.ml

clean:
	rm -rf _build
	rm -f com.docker.slirp
	rm -f com.docker.slirp.tgz
	rm -f bin/depends.ml

stage:
	mkdir -p _build/root/Contents/MacOS
	mv main.native com.docker.slirp
	mv com.docker.slirp _build/root/Contents/MacOS/com.docker.slirp
	dylibbundler -od -b \
	  -x _build/root/Contents/MacOS/com.docker.slirp \
	  -d _build/root/Contents/Resources/lib \
	  -p @executable_path/../Resources/lib
	tar -C _build/root -cvzf com.docker.slirp.tgz Contents

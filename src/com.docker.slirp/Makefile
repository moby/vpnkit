build: src/depends.ml
	ocaml pkg/pkg.ml build --vcs true --pinned true

src/depends.ml: src/depends.ml.in
	opam config subst src/depends.ml
	sed -e 's/%%HOSTNET_PINNED%%/$(shell opam info hostnet -f pinned)/g' -i tmp src/depends.ml

clean:
	rm -rf _build
	rm -f com.docker.slirp
	rm -f com.docker.slirp.tgz
	rm -f src/depends.ml

stage:
	mkdir -p _build/root/Contents/MacOS
	mv _build/src/main.native com.docker.slirp
	mv com.docker.slirp _build/root/Contents/MacOS/com.docker.slirp
	dylibbundler -od -b \
	  -x _build/root/Contents/MacOS/com.docker.slirp \
	  -d _build/root/Contents/Resources/lib \
	  -p @executable_path/../Resources/lib
	tar -C _build/root -cvzf com.docker.slirp.tgz Contents

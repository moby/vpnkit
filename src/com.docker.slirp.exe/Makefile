build: src/depends.ml
	ocaml pkg/pkg.ml build --vcs true --pinned true

src/depends.ml: src/depends.ml.in
	opam config subst src/depends.ml
	cp src/depends.ml src/depends.tmp
	sed -e 's/%%HOSTNET_PINNED%%/$(shell opam info hostnet -f pinned)/g' src/depends.tmp > src/depends.ml
	cp src/depends.ml src/depends.tmp
	sed -e 's/%%HVSOCK_PINNED%%/$(shell opam info hvsock -f pinned)/g' src/depends.tmp > src/depends.ml

clean:
	rm -rf _build/
	rm -f src/depends.ml

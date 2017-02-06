REPO_ROOT=$(shell git rev-parse --show-toplevel)
COMMIT_ID=$(shell git rev-parse HEAD)
LICENSEDIRS=$(REPO_ROOT)/repo/licenses
BINDIR?=$(shell pwd)

BINARIES :=
ARTEFACTS :=
ifeq ($(OS),Windows_NT)
	BINARIES += com.docker.slirp.exe
	ARTEFACTS += com.docker.slirp.exe
else
	BINARIES += com.docker.slirp
	ARTEFACTS += com.docker.slirp.tgz
endif

all: $(BINARIES)

.PHONY: install
install: $(BINARIES)
	cp $(BINARIES) '$(BINDIR)'

.PHONY: uninstall
uninstall:
	cd '$(BINDIR)' && for BINARY in $(BINARIES) ; do \
		rm -f $$BINARY ; \
	done

artefacts: $(ARTEFACTS)

src/bin/depends.ml: src/bin/depends.ml.in
	$(OPAMFLAGS) opam config subst src/bin/depends.ml || true
	cp src/bin/depends.ml src/bin/depends.tmp
	sed -e 's/££VERSION££/$(shell git rev-parse HEAD)/g' src/bin/depends.tmp > src/bin/depends.ml
	cp src/bin/depends.ml src/bin/depends.tmp
	sed -e 's/££HOSTNET_PINNED££/$(shell opam info hostnet -f pinned)/g' src/bin/depends.tmp > src/bin/depends.ml
	cp src/bin/depends.ml src/bin/depends.tmp
	sed -e 's/££HVSOCK_PINNED££/$(shell opam info hvsock -f pinned)/g' src/bin/depends.tmp > src/bin/depends.ml

com.docker.slirp.tgz: com.docker.slirp
	mkdir -p _build/root/Contents/MacOS
	cp com.docker.slirp _build/root/Contents/MacOS/com.docker.slirp
	dylibbundler -od -b \
		-x _build/root/Contents/MacOS/com.docker.slirp \
		-d _build/root/Contents/Resources/lib \
		-p @executable_path/../Resources/lib
	tar -C _build/root -cvzf com.docker.slirp.tgz Contents

.PHONY: com.docker.slirp.exe
com.docker.slirp.exe: src/bin/depends.ml setup.data
	ocaml setup.ml -build
	cp _build/src/bin/main.native com.docker.slirp.exe

.PHONY: com.docker.slirp
com.docker.slirp: src/bin/depends.ml setup.data
	ocaml setup.ml -build
	cp _build/src/bin/main.native com.docker.slirp

setup.data: _oasis
	oasis setup
	ocaml setup.ml -configure --disable-tests

.PHONY: test
test: _oasis
	oasis setup
	ocaml setup.ml -configure --enable-tests
	ocaml setup.ml -build
	ocaml setup.ml -test

.PHONY: OSS-LICENSES
OSS-LICENSES:
	mkdir -p $(LICENSEDIRS)
	cd $(LICENSEDIRS) && \
	  $(OPAMFLAGS) $(REPO_ROOT)/repo/opam-licenses.sh slirp
	$(REPO_ROOT)/repo/list-licenses.sh $(LICENSEDIRS) > OSS-LICENSES

.PHONY: COMMIT
COMMIT:
	@echo $(COMMIT_ID) > COMMIT

.PHONY: clean
clean:
	rm -rf _build
	rm -f com.docker.slirp
	rm -f com.docker.slirp.tgz
	rm -f src/bin/depends.ml
	rm -f setup.data

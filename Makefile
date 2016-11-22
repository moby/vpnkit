REPO_ROOT=$(shell git rev-parse --show-toplevel)
COMMIT_ID=$(shell git rev-parse HEAD)
EXEDIR=C:\projects\vpnkit
LICENSEDIRS=$(REPO_ROOT)/opam/licenses

.PHONY: com.docker.slirp.exe com.docker.slirp.tgz install uninstall OSS-LICENSES COMMIT

TARGETS :=
ifeq ($(OS),Windows_NT)
	TARGETS += com.docker.slirp.exe
else
	TARGETS += com.docker.slirp.tgz
endif

all: $(TARGETS)

src/bin/depends.ml: src/bin/depends.ml.in
	$(OPAMFLAGS) opam config subst src/bin/depends.ml || true
	cp src/bin/depends.ml src/bin/depends.tmp
	sed -e 's/%%VERSION%%/$(shell git rev-parse HEAD)/g' src/bin/depends.tmp > src/bin/depends.ml
	cp src/bin/depends.ml src/bin/depends.tmp
	sed -e 's/%%HOSTNET_PINNED%%/$(shell opam info hostnet -f pinned)/g' src/bin/depends.tmp > src/bin/depends.ml
	cp src/bin/depends.ml src/bin/depends.tmp
	sed -e 's/%%HVSOCK_PINNED%%/$(shell opam info hvsock -f pinned)/g' src/bin/depends.tmp > src/bin/depends.ml

com.docker.slirp.tgz: src/bin/depends.ml setup.data
	ocaml setup.ml -build
	mkdir -p _build/root/Contents/MacOS
	cp _build/src/bin/main.native _build/root/Contents/MacOS/com.docker.slirp
	dylibbundler -od -b \
		-x _build/root/Contents/MacOS/com.docker.slirp \
		-d _build/root/Contents/Resources/lib \
		-p @executable_path/../Resources/lib
	tar -C _build/root -cvzf com.docker.slirp.tgz Contents

com.docker.slirp.exe: src/bin/depends.ml setup.data
	ocaml setup.ml -build
	cp _build/src/bin/main.native com.docker.slirp.exe

setup.data: _oasis
	oasis setup
	ocaml setup.ml -configure --enable-tests

.PHONY: test
test: setup.data
	ocaml setup.ml -build
	ocaml setup.ml -test

install:
	cp com.docker.slirp.exe '$(EXEDIR)'

uninstall:
	@echo uninstall not implemented

OSS-LICENSES:
	mkdir -p $(LICENSEDIRS)
	cd $(LICENSEDIRS) && \
	  $(OPAMFLAGS) $(REPO_ROOT)/opam/opam-licenses.sh slirp
	$(REPO_ROOT)/opam/list-licenses.sh $(LICENSEDIRS) > OSS-LICENSES

COMMIT:
	@echo $(COMMIT_ID) > COMMIT

clean:
	rm -rf _build
	rm -f com.docker.slirp
	rm -f com.docker.slirp.tgz
	rm -f src/bin/depends.ml

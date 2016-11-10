REPO_ROOT=$(shell git rev-parse --show-toplevel)
COMMIT_ID=$(shell git rev-parse HEAD)
MACOSX_DEPLOYMENT_TARGET?=10.10
EXEDIR=C:\projects\vpnkit
LICENSEDIRS=$(REPO_ROOT)/opam/licenses

.PHONY: com.docker.slirp.exe com.docker.slirp.tgz install uninstall OSS-LICENSES COMMIT

TARGETS :=
ifeq ($(OS),Windows_NT)
	TARGETS += com.docker.slirp.exe
else
	TARGETS += com.docker.slirp.tgz
endif

ifeq ($(OS),Windows_NT)
	OPAM_REPO=$(shell cygpath.exe -w "$(REPO_ROOT)/opam/win32")
else
	OPAM_REPO=$(REPO_ROOT)/opam/darwin
endif

ifeq ($(OS),Windows_NT)
	OPAM_COMP="4.03.0+mingw64c"
else
	OPAM_COMP="4.03.0"
endif

ifeq ($(OS),Windows_NT)
	OPAMROOT=$(shell cygpath.exe -w "$(REPO_ROOT)/_build/opam")
else
	OPAMROOT=$(REPO_ROOT)/_build/opam
endif

DEPEXT = depext
ifeq ($(OS),Windows_NT)
	DEPEXT += depext-cygwinports
endif

# Overriding the OPAM_FLAGS is intended for CI
ifeq ($(CUSTOM_OPAM),1)
OPAMFLAGS=MACOSX_DEPLOYMENT_TARGET=$(MACOSX_DEPLOYMENT_TARGET) \
	  OPAMROOT="$(OPAMROOT)" \
	  OPAMYES=1 OPAMCOLORS=1
ifeq ($(OS),Windows_NT)
	OPAMFLAGS += \
	  PATH="${REPO_ROOT}/_build/opam/${OPAM_COMP}/bin:${PATH}"
endif
endif

all: $(TARGETS)

depends:
	mkdir -p $(OPAMROOT)
	$(OPAMFLAGS) opam init -n --comp=$(OPAM_COMP) --switch=$(OPAM_COMP) \
	  local "$(OPAM_REPO)"
	$(OPAMFLAGS) opam update -u -y
	$(OPAMFLAGS) opam install $(DEPEXT) -y
	$(OPAMFLAGS) OPAMBUILDTEST=1 opam depext -u slirp
	# Don't run all the unit tests of all upstream packages in the universe for speed
	$(OPAMFLAGS) opam install $(shell ls -1 $(OPAM_REPO)/packages/upstream) -y
	$(OPAMFLAGS) OPAMVERBOSE=1 opam install --deps-only slirp -y
	# ... but install tcpip with tests enabled
	$(OPAMFLAGS) OPAMVERBOSE=1 opam reinstall tcpip -y -t

src/bin/depends.ml: src/bin/depends.ml.in
	$(OPAMFLAGS) opam config subst src/bin/depends.ml
	cp src/bin/depends.ml src/bin/depends.tmp
	sed -e 's/%%VERSION%%/$(shell git rev-parse HEAD)/g' src/bin/depends.tmp > src/bin/depends.ml
	cp src/bin/depends.ml src/bin/depends.tmp
	sed -e 's/%%HOSTNET_PINNED%%/$(shell opam info hostnet -f pinned)/g' src/bin/depends.tmp > src/bin/depends.ml
	cp src/bin/depends.ml src/bin/depends.tmp
	sed -e 's/%%HVSOCK_PINNED%%/$(shell opam info hvsock -f pinned)/g' src/bin/depends.tmp > src/bin/depends.ml

com.docker.slirp.tgz: src/bin/depends.ml src/setup.data
	cd src/ && $(OPAMFLAGS) opam config exec -- ocaml setup.ml -build
	mkdir -p src/_build/root/Contents/MacOS
	cp src/_build/bin/main.native src/_build/root/Contents/MacOS/com.docker.slirp
	cd src && dylibbundler -od -b \
		-x _build/root/Contents/MacOS/com.docker.slirp \
		-d _build/root/Contents/Resources/lib \
		-p @executable_path/../Resources/lib
	tar -C src/_build/root -cvzf ../com.docker.slirp.tgz Contents

com.docker.slirp.exe: src/bin/depends.ml src/setup.data
	cd src/ && $(OPAMFLAGS) opam config exec -- ocaml setup.ml -build
	cp src/_build/bin/main.native com.docker.slirp.exe

src/setup.data: src/_oasis
	cd src && $(OPAMFLAGS) opam config exec -- oasis setup
	cd src && $(OPAMFLAGS) opam config exec -- ocaml setup.ml -configure --enable-tests

.PHONY: test
test: src/setup.data
	cd src && $(OPAMFLAGS) opam config exec -- ocaml setup.ml -build
	cd src && $(OPAMFLAGS) opam config exec -- ocaml setup.ml -test

install:
	cp src/com.docker.slirp.exe '$(EXEDIR)'

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
	rm -rf src/_build
	rm -f com.docker.slirp
	rm -f com.docker.slirp.tgz
	rm -f src/bin/depends.ml

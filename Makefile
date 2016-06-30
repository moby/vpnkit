REPO_ROOT=$(shell git rev-parse --show-toplevel)
COMMIT_ID=$(shell git rev-parse HEAD)
MACOSX_DEPLOYMENT_TARGET?=10.10
EXEDIR=C:\projects\vpnkit
LICENSEDIRS=$(REPO_ROOT)/opam/licenses

.PHONY: com.docker.slirp.exe com.docker.slirp install uninstall OSS-LICENSES COMMIT

TARGETS :=
ifeq ($(OS),Windows_NT)
	TARGETS += com.docker.slirp.exe
else
	TARGETS += com.docker.slirp
endif

ifeq ($(OS),Windows_NT)
	OPAM_REPO=$(shell cygpath.exe -w "$(REPO_ROOT)/opam/win32")
else
	OPAM_REPO=$(REPO_ROOT)/opam/darwin
endif

ifeq ($(OS),Windows_NT)
	OPAM_COMP="4.02.3+mingw64c"
else
	OPAM_COMP="4.02.3"
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

OPAMFLAGS=MACOSX_DEPLOYMENT_TARGET=$(MACOSX_DEPLOYMENT_TARGET) \
	  OPAMROOT="$(OPAMROOT)" \
	  OPAMYES=1 OPAMCOLORS=1
ifeq ($(OS),Windows_NT)
	OPAMFLAGS += \
	  PATH="${REPO_ROOT}/_build/opam/${OPAM_COMP}/bin:${PATH}"
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
	# Please do run the unit tests for our packages
	$(OPAMFLAGS) opam install --deps-only slirp -y -t

com.docker.slirp:
	$(OPAMFLAGS) opam config exec -- $(MAKE) -C src/com.docker.slirp build test
	cp src/com.docker.slirp/_build/src/main.native com.docker.slirp

com.docker.slirp.exe:
	cd src/com.docker.slirp.exe && \
	$(OPAMFLAGS) opam config exec -- \
	sh -c "oasis setup && ./configure --enable-tests && make && make test"
	cp src/com.docker.slirp.exe/_build/src/main.native com.docker.slirp.exe

install:
	cp src/com.docker.slirp.exe/com.docker.slirp.exe '$(EXEDIR)'
	cp src/com.docker.slirp.exe/register.ps1 '$(EXEDIR)'

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
	for pkg in `ls src/`; do \
	  (cd src/$$pkg && ocamlbuild -clean && rm -f setup.data); \
	done

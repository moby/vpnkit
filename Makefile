REPO_ROOT=$(shell git rev-parse --show-toplevel)
MACOSX_DEPLOYMENT_TARGET?=10.10
EXEDIR=C:\projects\vpnkit
LICENSEDIRS=$(REPO_ROOT)/opam/licenses

.PHONY: com.docker.slirp.exe com.docker.slirp install uninstall OSS-LICENSES

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
	OPAM_COMP="4.02.3+mingw32c"
else
	OPAM_COMP="4.02.3"
endif

ifeq ($(OS),Windows_NT)
	OPAMROOT=$(shell cygpath.exe -w "$(REPO_ROOT)/_build/opam")
else
	OPAMROOT=$(REPO_ROOT)/_build/opam
endif



OPAMFLAGS=MACOSX_DEPLOYMENT_TARGET=$(MACOSX_DEPLOYMENT_TARGET) \
	  OPAMROOT="$(OPAMROOT)" \
	  OPAMYES=1 OPAMCOLORS=1

all: $(TARGETS)

depends:
	mkdir -p $(OPAMROOT)
	$(OPAMFLAGS) opam init -n --comp=$(OPAM_COMP) --switch=$(OPAM_COMP) \
	  local "$(OPAM_REPO)"
	$(OPAMFLAGS) opam update -u -y
	$(OPAMFLAGS) opam install depext -y
	$(OPAMFLAGS) opam depext -u slirp
	$(OPAMFLAGS) opam install --deps-only slirp -y

com.docker.slirp:
	$(OPAMFLAGS) opam config exec -- $(MAKE) -C src/com.docker.slirp

com.docker.slirp.exe:
	cd src/com.docker.slirp.exe && \
	$(OPAMLFAGS) opam config exec -- \
	sh -c \
	  "oasis setup && \
	  ./configure && \
	  make && \
	  cp _build/src/main.native com.docker.slirp.exe"

install:
	cp src/com.docker.slirp.exe/com.docker.slirp.exe '$(EXEDIR)'
	cp src/com.docker.slirp.exe/register.ps1 '$(EXEDIR)'

uninstall:
	echo uninstall not implemented

OSS-LICENSES:
	mkdir -p $(LICENSEDIRS)
	cd $(LICENSEDIRS) && \
	  $(OPAMFLAGS) $(REPO_ROOT)/opam/opam-licenses.sh slirp
	$(REPO_ROOT)/opam/list-licenses.sh $(OPAMROOT) > OSS-LICENSES

clean:
	for pkg in `ls src/`; do \
	  (cd src/$$pkg && ocamlbuild -clean && rm -f setup.data); \
	done

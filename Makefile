MACOSX_DEPLOYMENT_TARGET?=10.10
EXEDIR=C:\projects\vpnkit
OPAMROOT=$(shell pwd)/_build/opam
OPAMFLAGS=MACOSX_DEPLOYMENT_TARGET=$(MACOSX_DEPLOYMENT_TARGET) \
	  OPAMROOT=$(OPAMROOT) \
	  OPAMYES=1 OPAMCOLORS=1

.PHONY: com.docker.slirp.exe com.docker.slirp install uninstall

TARGETS :=
ifeq ($(OS),Windows_NT)
	TARGETS += com.docker.slirp.exe
else
	TARGETS += com.docker.slirp
endif

ifeq ($(OS),Windows_NT)
	OPAM_REPO=$(REPO_ROOT)/opam/win32
else
	OPAM_REPO=$(REPO_ROOT)/opam/darwin
endif

ifeq ($(OS),Windows_NT)
	OPAM_COMP="4.02.3+mingw32c"
else
	OPAM_COMP="4.02.3"
endif

all: $(TARGETS)

depends:
	mkdir -p $(OPAMROOT)
	$(OPAMFLAGS) opam init -n --comp=$(OPAM_COMP) local $(OPAM_REPO)
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

clean:
	for pkg in `ls src/`; do \
	  (cd src/$$pkg && ocamlbuild -clean && rm -f setup.data); \
	done

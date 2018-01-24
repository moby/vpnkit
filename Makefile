REPO_ROOT=$(shell git rev-parse --show-toplevel)
ifeq ($(OS),Windows_NT)
  OPAM_COMP?=4.06.0+mingw64c
  OPAM_REPO?=repo/win32
  OPAMROOT?=$(shell cygpath -w "$(REPO_ROOT)/_build/opam")
else
  OPAM_COMP?=4.06.0
  OPAM_REPO?=repo/darwin
  OPAMROOT?=$(REPO_ROOT)/_build/opam
endif

LICENSEDIRS=$(REPO_ROOT)/repo/licenses
BINDIR?=$(shell pwd)

BINARIES := vpnkit.exe
ARTEFACTS :=
ifeq ($(OS),Windows_NT)
	ARTEFACTS += vpnkit.exe
else
	ARTEFACTS += vpnkit.tgz
endif

all: $(OPAMROOT) $(BINARIES)

$(OPAMROOT):
	OPAMROOT=$(OPAMROOT) OPAM_COMP=$(OPAM_COMP) OPAM_REPO=$(OPAM_REPO) ./scripts/depends.sh

.PHONY: install
install: $(BINARIES)
	cp $(BINARIES) '$(BINDIR)'

.PHONY: uninstall
uninstall:
	cd '$(BINDIR)' && for BINARY in $(BINARIES) ; do \
		rm -f $$BINARY ; \
	done

artefacts: $(ARTEFACTS)

vpnkit.tgz: vpnkit.exe
	mkdir -p _build/root/Contents/Resources/bin
	cp vpnkit.exe _build/root/Contents/Resources/bin/vpnkit
	dylibbundler -od -b \
		-x _build/root/Contents/Resources/bin/vpnkit \
		-d _build/root/Contents/Resources/lib \
		-p @executable_path/../lib
	tar -C _build/root -cvzf vpnkit.tgz Contents

.PHONY: vpnkit.exe
vpnkit.exe: $(OPAMROOT)
	opam config --root $(OPAMROOT) --switch $(OPAM_COMP) exec -- sh -c 'jbuilder build --dev src/bin/main.exe'
	cp _build/default/src/bin/main.exe vpnkit.exe

.PHONY: test
test: $(OPAMROOT)
	opam config --root $(OPAMROOT) --switch $(OPAM_COMP) exec -- sh -c 'jbuilder build --dev src/hostnet_test/main.exe'
	# One test requires 1026 file descriptors
	ulimit -n 1500 && ./_build/default/src/hostnet_test/main.exe

# Published as a artifact.
.PHONY: OSS-LICENSES
OSS-LICENSES:
	@echo "  GEN     " $@
	@mkdir -p $(LICENSEDIRS)
	@cd $(LICENSEDIRS) && \
	  $(OPAMFLAGS) $(REPO_ROOT)/repo/opam-licenses.sh vpnkit
	@$(REPO_ROOT)/repo/list-licenses.sh $(LICENSEDIRS) > $@.tmp
	@mv $@.tmp $@

# Published as a artifact.
.PHONY: COMMIT
COMMIT:
	@echo "  GEN     " $@
	@git rev-parse HEAD > $@.tmp
	@mv $@.tmp $@

.PHONY: clean
clean:	
	rm -rf _build
	rm -f vpnkit.exe
	rm -f vpnkit.tgz

REPO=../../mirage/opam-repository
PACKAGES=$(REPO)/packages
# until we have https://github.com/ocaml/opam-publish/issues/38
pkg-%:
	topkg opam pkg -n $*
	mkdir -p $(PACKAGES)/$*
	cp -r _build/$*.* $(PACKAGES)/$*/
	cd $(PACKAGES) && git add $*

PKGS=$(basename $(wildcard *.opam))
opam-pkg:
	$(MAKE) $(PKGS:%=pkg-%)

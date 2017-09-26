REPO_ROOT=$(shell git rev-parse --show-toplevel)
COMMIT_ID=$(shell git rev-parse HEAD)
LICENSEDIRS=$(REPO_ROOT)/repo/licenses
BINDIR?=$(shell pwd)

BINARIES := vpnkit.exe
ARTEFACTS :=
ifeq ($(OS),Windows_NT)
	ARTEFACTS += vpnkit.exe libgmp-10.dll
	BINARIES += libgmp-10.dll
else
	ARTEFACTS += vpnkit.tgz
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

vpnkit.tgz: vpnkit.exe
	mkdir -p _build/root/Contents/MacOS
	cp vpnkit.exe _build/root/Contents/MacOS/vpnkit
	dylibbundler -od -b \
		-x _build/root/Contents/MacOS/vpnkit \
		-d _build/root/Contents/Resources/lib \
		-p @executable_path/../Resources/lib
	tar -C _build/root -cvzf vpnkit.tgz Contents

.PHONY: vpnkit.exe
vpnkit.exe:
	jbuilder build --dev src/bin/main.exe
	cp _build/default/src/bin/main.exe vpnkit.exe

.PHONY: libgmp-10.dll
libgmp-10.dll:
	cp /usr/x86_64-w64-mingw32/sys-root/mingw/bin/libgmp-10.dll .

.PHONY: test
test:
	jbuilder build --dev src/hostnet_test/main.exe
	./_build/default/src/hostnet_test/main.exe

.PHONY: OSS-LICENSES
OSS-LICENSES:
	mkdir -p $(LICENSEDIRS)
	cd $(LICENSEDIRS) && \
	  $(OPAMFLAGS) $(REPO_ROOT)/repo/opam-licenses.sh vpnkit
	$(REPO_ROOT)/repo/list-licenses.sh $(LICENSEDIRS) > OSS-LICENSES

.PHONY: COMMIT
COMMIT:
	@echo $(COMMIT_ID) > COMMIT

.PHONY: clean
clean:
	jbuilder clean
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

REPO_ROOT=$(shell git rev-parse --show-toplevel)
COMMIT_ID=$(shell git rev-parse HEAD)
LICENSEDIRS=$(REPO_ROOT)/repo/licenses
BINDIR?=$(shell pwd)

BINARIES := vpnkit.exe
ARTEFACTS :=
ifeq ($(OS),Windows_NT)
	ARTEFACTS += vpnkit.exe
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

src/bin/depends.ml: src/bin/depends.ml.in
	$(OPAMFLAGS) opam config subst src/bin/depends.ml || true
	cp src/bin/depends.ml src/bin/depends.tmp
	sed -e 's/££VERSION££/$(shell git rev-parse HEAD)/g' src/bin/depends.tmp > src/bin/depends.ml
	cp src/bin/depends.ml src/bin/depends.tmp
	sed -e 's/££HVSOCK_PINNED££/$(shell opam info hvsock -f pinned)/g' src/bin/depends.tmp > src/bin/depends.ml

vpnkit.tgz: vpnkit.exe
	mkdir -p _build/root/Contents/MacOS
	cp vpnkit.exe _build/root/Contents/MacOS/vpnkit
	dylibbundler -od -b \
		-x _build/root/Contents/MacOS/vpnkit \
		-d _build/root/Contents/Resources/lib \
		-p @executable_path/../Resources/lib
	tar -C _build/root -cvzf vpnkit.tgz Contents

.PHONY: vpnkit.exe
vpnkit.exe: src/bin/depends.ml
	jbuilder build --dev src/bin/main.exe
	cp _build/default/src/bin/main.exe vpnkit.exe

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
	rm -f src/bin/depends.ml

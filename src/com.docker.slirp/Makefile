TARGETS := build

all: $(TARGETS)

SETUP = ocaml setup.ml

setup.ml:
	oasis setup

build: setup.data
	$(SETUP) -build $(BUILDFLAGS)

doc: setup.data build
	$(SETUP) -doc $(DOCFLAGS)

test: setup.data build
	$(SETUP) -test $(TESTFLAGS)

install: setup.data
	$(SETUP) -install $(INSTALLFLAGS)

uninstall: setup.data
	$(SETUP) -uninstall $(UNINSTALLFLAGS)

reinstall: setup.data
	$(SETUP) -reinstall $(REINSTALLFLAGS)

setup.data: setup.ml
	$(SETUP) -configure $(CONFIGUREFLAGS)

configure:
	$(SETUP) -configure $(CONFIGUREFLAGS)

.PHONY: build doc test all install uninstall reinstall clean distclean configure

clean:
	rm -rf _build setup.data
	rm -f com.docker.slirp
	rm -f com.docker.slirp.tgz

stage:
	mkdir -p _build/root/Contents/MacOS
	mv main.native com.docker.slirp
	cp com.docker.slirp _build/root/Contents/MacOS/com.docker.slirp
	dylibbundler -od -b \
	  -x _build/root/Contents/MacOS/com.docker.slirp \
	  -d _build/root/Contents/Resources/lib \
	  -p @executable_path/../Resources/lib
	tar -C _build/root -cvzf com.docker.slirp.tgz Contents

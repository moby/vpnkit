TARGETS := build

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	TARGETS += bundle.tgz
endif

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

bundle.tgz: bundle
	tar -cvzf bundle.tgz _build/root

.PHONY: bundle
bundle: build
	mkdir -p _build/root/Contents/MacOS
	mv main.native com.docker.slirp
	cp com.docker.slirp _build/root/Contents/MacOS/com.docker.slirp
	dylibbundler -od -b \
	  -x _build/root/Contents/MacOS/com.docker.slirp \
	  -d _build/root/Contents/Resources/lib \
	  -p @executable_path/../Resources/lib

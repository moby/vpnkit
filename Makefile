.PHONY: com.docker.slirp.exe com.docker.slirp install uninstall

TARGETS :=
ifeq ($(OS),Windows_NT)
	TARGETS += com.docker.slirp.exe
else
	TARGETS += com.docker.slirp
endif

all: $(TARGETS)

EXEDIR=C:\projects\vpnkit

com.docker.slirp:
	$(MAKE) -C src/com.docker.slirp

depends:
	opam pin add -n proto-vmnet src/proto-vmnet -y
	opam pin add -n ofs src/ofs -y
	opam pin add -n hostnet src/hostnet -y
	opam pin add -n osx-daemon src/osx-daemon -y
	opam pin add -n osx-hyperkit src/osx-hyperkit -y
	opam pin add -n osx-hyperkit src/osx-hyperkit -y
	opam pin add -n lwt "https://github.com/dsheets/lwt.git#bad-library-search-path-pthread-2.5.1" -y
	opam pin add -n charrua-core "git://github.com/djs55/charrua-core#0.3-beta" -y
	opam pin add -n mirage "git://github.com/djs55/mirage#3.0.0-beta" -y
	opam pin add -n mirage-types "git://github.com/djs55/mirage#3.0.0-beta" -y
	opam pin add -n mirage-types-lwt "git://github.com/djs55/mirage#3.0.0-beta" -y
	opam pin add -n tcpip "git://github.com/djs55/mirage-tcpip#3.0.0-beta3" -y
ifeq ($(OS),Windows_NT)
	opam pin add -n slirp src/com.docker.slirp.exe -y
else
	opam pin add -n slirp src/com.docker.slirp -y
endif
	opam depext -u slirp
	opam install --deps-only slirp -y

com.docker.slirp.exe:
	cd src/com.docker.slirp.exe && \
	oasis setup && \
	./configure && \
	make && \
	cp _build/src/main.native com.docker.slirp.exe

install:
	cp src/com.docker.slirp.exe/com.docker.slirp.exe '$(EXEDIR)'
	cp src/com.docker.slirp.exe/register.ps1 '$(EXEDIR)'

uninstall:
	echo uninstall not implemented

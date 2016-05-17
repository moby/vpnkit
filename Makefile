.PHONY: com.docker.slirp.exe install uninstall

EXEDIR=C:\projects\vpnkit

com.docker.slirp:
	cd src/com.docker.slirp && ./configure && make && cp _build/src/main.native com.docker.slirp

com.docker.slirp.exe:
	cd src/com.docker.slirp.exe && ./configure && make && cp _build/src/main.native com.docker.slirp.exe

install:
	cp src/com.docker.slirp.exe/com.docker.slirp.exe '$(EXEDIR)'
	cp src/com.docker.slirp.exe/register.ps1 '$(EXEDIR)'

uninstall:
	echo uninstall

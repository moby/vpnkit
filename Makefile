.PHONY: com.docker.slirp.exe install uninstall

EXEDIR=C:\projects\hyperkit-net\com.docker.slirp.exe

com.docker.slirp:
	cd v1/cmd/com.docker.slirp && ./configure && make && cp _build/src/main.native com.docker.slirp

com.docker.slirp.exe:
	cd v1/cmd/com.docker.slirp.exe && ./configure && make && cp _build/src/main.native com.docker.slirp.exe

install:
	cp v1/cmd/com.docker.slirp.exe/com.docker.slirp.exe '$(EXEDIR)'

uninstall:
	echo uninstall


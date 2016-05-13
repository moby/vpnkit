.PHONY: com.docker.slirp.exe install uninstall

com.docker.slirp.exe:
	cd v1/cmd/com.docker.slirp.exe && ./configure && make && cp _build/src/main.native com.docker.slirp.exe

install:
	echo install

uninstall:
	echo uninstall


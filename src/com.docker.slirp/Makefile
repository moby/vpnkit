all:
	ocaml pkg/pkg.ml build

clean:
	rm -rf _build
	rm -f com.docker.slirp
	rm -f com.docker.slirp.tgz

stage:
	mkdir -p _build/root/Contents/MacOS
	mv _build/main.native com.docker.slirp
	mv com.docker.slirp _build/root/Contents/MacOS/com.docker.slirp
	dylibbundler -od -b \
	  -x _build/root/Contents/MacOS/com.docker.slirp \
	  -d _build/root/Contents/Resources/lib \
	  -p @executable_path/../Resources/lib
	tar -C _build/root -cvzf com.docker.slirp.tgz Contents

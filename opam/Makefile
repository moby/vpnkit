# The exact list is `ls packages/local` + $PKGS
PKGS = alcotest depext

update-osx:
	./update-upstream.sh $(PKGS)

update-win:
	OPAM_OS="win32" OPAM_SWITH="4.02.3+mingw32c" \
	OPAM_REPO="https://github.com/fdopen/opam-repository-mingw.git" \
	./update-upstream.sh $(PKGS)
commit:
	$(MAKE) update-osx
	$(MAKE) update-win
	git add win32/packages/upstream
	git add darwin/packages/upstream
	git commit -a -s -m "AUTO: Update upstream packages"

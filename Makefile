build: vpnkit.exe

.PHONY: vpnkit.exe
vpnkit.exe:
	opam exec -- dune build --profile release @install

.PHONY: ocaml
ocaml:
	opam switch create ./ ocaml-base-compiler.4.14.3 --no-install
	opam repo add archive-without-constraint git+https://github.com/tarides/moby-vpnkit-opam-repository-archive#remove-dune-upper-constraint
	opam pin add vpnkit . --kind=path --no-action

.PHONY: depends
depends:
	opam install vpnkit --deps-only --with-test

.PHONY: test
test:
	opam exec -- dune build @runtest @e2e

deps.csv:
	opam list \
		--installed \
		--required-by=vpnkit \
		--recursive \
		--columns name,package,license: \
		--separator=, \
		--nobuild \
		--color=never \
		> $@

licenses.json: deps.csv
	opam exec -- dune exec ./scripts/licenses.exe -- -out $@ -in $?

vpnkit.tgz:
	opam exec -- dune build --profile release @install
	opam exec -- dune exec ./scripts/mac_package.exe -- -out $@ -in _build/install/default/bin/vpnkit

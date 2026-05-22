build: vpnkit.exe

.PHONY: vpnkit.exe
vpnkit.exe:
	opam exec -- dune build --profile release

.PHONY: ocaml
ocaml:
	ocaml -version || opam init --compiler=4.14.0
	opam pin add vpnkit . -n

.PHONY: depends
depends:
	opam install --deps-only -t vpnkit

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

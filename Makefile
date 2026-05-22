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

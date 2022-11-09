REPO_ROOT=$(shell git rev-parse --show-toplevel)

build: vpnkit.exe

vpnkit.exe:
	opam exec -- dune build --profile release

ocaml:
	ocaml -version || opam init --compiler=4.14.0
	opam pin add vpnkit . -n

depends:
	opam install --deps-only -t vpnkit

test:
	opam exec -- dune test
	opam exec -- dune build @e2e

%: %.in
	@echo "  GEN     " $@
	@sed -e "s/@COMMIT@/$$(git rev-parse HEAD)/" $< >$@.tmp
	@mv $@.tmp $@

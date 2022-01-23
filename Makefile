REPO_ROOT=$(shell git rev-parse --show-toplevel)

build: vpnkit.exe

vpnkit.exe:
	opam exec -- dune build --profile release

depends:
	opam install vpnkit alcotest ounit -y

ocaml:
	ocaml -version || opam init --compiler=4.12.0
	# Can be removed after we upgrade tcpip
	opam pin configurator --dev-repo -n
	# Fix for Apple Silicon codesign issue
	opam pin add omake "https://github.com/ocaml-omake/omake.git#0e4aef74dfe005b4e880cd13c08f7c57fa4a030b" -n
	# Fix for OCaml 4.12 build
	opam pin add uwt "https://github.com/fdopen/uwt.git#c43349bf3689181756feb341e3896d4a0a695523" -n
	opam pin add hvsock.3.0.0 "https://github.com/djs55/ocaml-hvsock.git#release.3.0.0" -n
	opam pin add protocol-9p.2.0.2 "https://github.com/djs55/ocaml-9p.git#cstruct.length" -n
	opam pin add protocol-9p-unix.2.0.2 "https://github.com/djs55/ocaml-9p.git#cstruct.length" -n
	opam pin add vpnkit . -n

test:
	opam exec -- dune test

%: %.in
	@echo "  GEN     " $@
	@sed -e "s/@COMMIT@/$$(git rev-parse HEAD)/" $< >$@.tmp
	@mv $@.tmp $@
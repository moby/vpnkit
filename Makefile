build: vpnkit.exe

vpnkit.exe:
	opam exec -- dune build --profile release

ocaml:
	ocaml -version || opam init --compiler=4.14.0
	opam pin add vpnkit . -n

depends:
	opam install --deps-only -t vpnkit

test:
	opam exec -- dune build @runtest @e2e

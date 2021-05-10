all: vpnkit.exe

.PHONY: vpnkit.exe
vpnkit.exe:
	dune build src/bin/main.exe
	cp _build/default/src/bin/main.exe vpnkit.exe

%: %.in
	@echo "  GEN     " $@
	@sed -e "s/@COMMIT@/$$(git rev-parse HEAD)/" $< >$@.tmp
	@mv $@.tmp $@

.PHONY: test
test:
	dune runtest --no-buffer
	dune build src/hostnet_test/main.exe
	cp -r go/test_inputs _build/default/src/hostnet_test/
# One test requires 1026 file descriptors
	ulimit -n 1500 && ./_build/default/src/hostnet_test/main.exe

.PHONY: clean
clean:
	rm -rf _build
	rm -f vpnkit.exe
	rm -f vpnkit.tgz

e2e-vpnkit-tap-vsockd:
	docker build -t vpnkit-host .
	docker build -t vpnkit-guest c/vpnkit-tap-vsockd
	docker rm -f vpnkit-test-host vpnkit-test-guest || echo "no garbage container"
	docker volume rm -f vpnkit-test
	docker volume create vpnkit-test
	docker run -d --name vpnkit-test-host -v vpnkit-test:/shared vpnkit-host /vpnkit --ethernet /shared/vpnkit.sock
	docker run -d --name vpnkit-test-guest --network=none --cap-add NET_ADMIN -v vpnkit-test:/shared vpnkit-guest \
		sh -c "mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && /sbin/vpnkit-tap-vsockd --tap eth0 --path /shared/vpnkit.sock"
	docker exec vpnkit-test-guest sh -c "dhclient eth0 && wget http://www.google.com"
	docker rm -f vpnkit-test-host vpnkit-test-guest
	docker volume rm -f vpnkit-test

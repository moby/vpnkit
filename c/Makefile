.PHONY=all build-in-container

all:
	make -C vpnkit-tap-vsockd
	make -C vpnkit-9pmount-vsock

build-in-container:
	make -C vpnkit-tap-vsockd build-in-container
	make -C vpnkit-9pmount-vsock build-in-container

clean:
	make -C vpnkit-tap-vsockd clean
	make -C vpnkit-9pmount-vsock clean

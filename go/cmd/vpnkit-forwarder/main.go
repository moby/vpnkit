package main

import (
	"flag"
	"io"
	"log"
	"net"

	"github.com/linuxkit/virtsock/pkg/hvsock"
	"github.com/linuxkit/virtsock/pkg/vsock"
	"github.com/moby/vpnkit/go/pkg/libproxy"
)

// Listen on virtio-vsock and AF_HYPERV for multiplexed connections
func main() {
	var (
		vsockPort = flag.Int("vsockPort", 62373, "virtio-vsock port")
		hvGUID    = flag.String("hvGuid", "0B95756A-9985-48AD-9470-78E060895BE7", "Hyper-V service GUID")
		listener  net.Listener
	)
	flag.Parse()

	quit := make(chan struct{})
	defer close(quit)

	vsock, err := vsock.Listen(vsock.CIDAny, uint32(*vsockPort))
	if err != nil {
		log.Printf("Failed to bind to vsock port %d: %#v", vsockPort, err)
	} else {
		listener = vsock
	}
	svcid, _ := hvsock.GUIDFromString(*hvGUID)
	hvsock, err := hvsock.Listen(hvsock.HypervAddr{VMID: hvsock.GUIDWildcard, ServiceID: svcid})
	if err != nil {
		log.Printf("Failed to bind hvsock guid: %s: %#v", *hvGUID, err)
	} else {
		listener = hvsock
	}

	if listener == nil {
		log.Fatal("Failed to bind vsock or hvsock")
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %#v", err)
			return // no more listening
		}
		go handleConn(conn, quit)
	}
}

// handle every AF_VSOCK connection to the multiplexer
func handleConn(rw io.ReadWriteCloser, quit chan struct{}) {
	defer rw.Close()

	mux := libproxy.NewMultiplexer("local", rw)
	mux.Run()
	for {
		conn, destination, err := mux.Accept()
		if err != nil {
			log.Printf("Error accepting subconnection: %v", err)
			return
		}
		go libproxy.Forward(conn, *destination, quit)
	}
}

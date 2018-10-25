package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/linuxkit/virtsock/pkg/hvsock"
	"github.com/linuxkit/virtsock/pkg/vsock"
	"github.com/moby/vpnkit/go/pkg/libproxy"
)

// Listen on either AF_VSOCK or AF_HVSOCK (depending on the kernel) for multiplexed connections
func main() {
	var (
		port     int
		listener net.Listener
	)
	flag.IntVar(&port, "port", 0, "AF_VSOCK port")
	flag.Parse()

	quit := make(chan struct{})
	defer close(quit)

	if HvsockSupported() {
		listener = hyperVListener(port)
	} else {
		listener = vsockListener(port)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			return // no more listening
		}
		go handleConn(conn, quit)
	}
}

func hyperVListener(port int) net.Listener {
	serviceID := fmt.Sprintf("%08x-FACB-11E6-BD58-64006A7986D3", port)
	svcid, _ := hvsock.GUIDFromString(serviceID)
	l, err := hvsock.Listen(hvsock.HypervAddr{VMID: hvsock.GUIDWildcard, ServiceID: svcid})
	if err != nil {
		log.Fatalf("Failed to bind AF_HVSOCK guid: %s: %v", serviceID, err)
	}
	return l
}

func vsockListener(port int) net.Listener {
	l, err := vsock.Listen(vsock.CIDAny, uint32(port))
	if err != nil {
		log.Fatalf("Failed to bind to AF_VSOCK port %d: %v", port, err)
	}
	return l
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

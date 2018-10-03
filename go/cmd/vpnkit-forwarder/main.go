package main

import (
	"flag"
	"log"
	"net"

	"github.com/linuxkit/virtsock/pkg/hvsock"
	"github.com/linuxkit/virtsock/pkg/vsock"
	"github.com/moby/vpnkit/go/pkg/libproxy"
)

// Listen on virtio-vsock and AF_HYPERV for multiplexed connections
func manyPorts() {
	var (
		vsockPort = flag.Int("vsockPort", 62373, "virtio-vsock port")
		hvGUID    = flag.String("hvGuid", "0B95756A-9985-48AD-9470-78E060895BE7", "Hyper-V service GUID")
		listener  net.Listener
	)
	flag.Parse()

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

	quit := make(chan struct{})
	defer close(quit)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %#v", err)
			return // no more listening
		}
		go func() {
			defer conn.Close()
			if err := libproxy.HandleMultiplexedConnections(conn, quit); err != nil {
				log.Println(err)
			}
		}()
	}
}

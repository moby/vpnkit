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
	)
	flag.Parse()

	listeners := make([]net.Listener, 0)

	vsock, err := vsock.Listen(vsock.CIDAny, uint32(*vsockPort))
	if err != nil {
		log.Printf("Failed to bind to vsock port %d: %#v", vsockPort, err)
	} else {
		listeners = append(listeners, vsock)
	}
	svcid, _ := hvsock.GUIDFromString(*hvGUID)
	hvsock, err := hvsock.Listen(hvsock.HypervAddr{VMID: hvsock.GUIDWildcard, ServiceID: svcid})
	if err != nil {
		log.Printf("Failed to bind hvsock guid: %s: %#v", *hvGUID, err)
	} else {
		listeners = append(listeners, hvsock)
	}

	quit := make(chan bool)
	defer close(quit)

	for _, l := range listeners {
		go func(l net.Listener) {
			for {
				conn, err := l.Accept()
				if err != nil {
					log.Printf("Error accepting connection: %#v", err)
					return // no more listening
				}
				if err := libproxy.HandleMultiplexedConnections(conn, quit); err != nil {
					log.Println(err)
					conn.Close()
				}
			}
		}(l)
	}
	forever := make(chan int)
	<-forever
}

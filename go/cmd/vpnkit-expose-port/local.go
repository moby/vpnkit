package main

import (
	"log"
	"net"
	"os"
	"syscall"

	"github.com/moby/vpnkit/go/pkg/libproxy"
	"github.com/moby/vpnkit/go/pkg/vpnkit"
)

type localBind int

const (
	bestEffortLocalBind = localBind(0)
	alwaysLocalBind     = localBind(1)
	neverLocalBind      = localBind(2)
)

func maybeLocalBind(port vpnkit.Port, localBind localBind) {
	switch localBind {
	case alwaysLocalBind:
		ipP, err := listenInVM(port)
		if err != nil {
			sendError(err)
			// never get here
		}
		if ipP == nil {
			log.Printf("address only exists on the host: not binding inside the VM")
			return
		}
		go ipP.Run()
	case bestEffortLocalBind:
		ipP, err := listenInVM(port)
		if err != nil {
			log.Printf("ignoring the error binding in the VM for %s", port.String())
			return
		}
		if ipP == nil {
			log.Printf("address only exists on the host: not binding inside the VM")
			return
		}
		go ipP.Run()
	case neverLocalBind:
	}
}

// Best-effort attempt to listen on the address in the VM. This is for
// backwards compatibility with software that expects to be able to listen on
// 0.0.0.0 and then connect from within a container to the external port.
// If the address doesn't exist in the VM (i.e. it exists only on the host)
// then this is not a hard failure.
func listenInVM(port vpnkit.Port) (libproxy.Proxy, error) {
	host := &net.TCPAddr{IP: port.OutIP, Port: int(port.OutPort)}
	container := &net.TCPAddr{IP: port.InIP, Port: int(port.InPort)}

	ipP, err := libproxy.NewIPProxy(host, container)
	if err == nil {
		return ipP, nil
	}
	if opError, ok := err.(*net.OpError); ok {
		if syscallError, ok := opError.Err.(*os.SyscallError); ok {
			if syscallError.Err == syscall.EADDRNOTAVAIL {
				log.Printf("Address %s doesn't exist in the VM: only binding on the host", host)
				return nil, nil // Non-fatal error
			}
		}
	}
	return nil, err
}

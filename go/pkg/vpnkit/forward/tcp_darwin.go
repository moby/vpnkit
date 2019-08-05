//+build !windows

package forward

import (
	"net"

	"github.com/moby/vpnkit/go/pkg/vpnkit"
)

func listenTCP(port vpnkit.Port) (*net.TCPListener, bool, error) {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   port.OutIP,
		Port: int(port.OutPort),
	})

	if err != nil && isPermissionDenied(err) {
		// fall back to vmnetd
		l, err := listenTCPVmnet(port.OutIP, port.OutPort)
		return l, true, err
	}
	return l, false, err
}

func closeTCP(port vpnkit.Port, vmnetd bool, l *net.TCPListener) error {
	if vmnetd {
		return closeTCPVmnet(port.OutIP, port.OutPort, l)
	}
	return l.Close()
}

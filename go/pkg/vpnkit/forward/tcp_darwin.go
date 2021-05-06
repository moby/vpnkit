//+build !windows

package forward

import (
	"net"

	"github.com/moby/vpnkit/go/pkg/vpnkit"
)

func listenTCP(port vpnkit.Port) (net.Listener, error) {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   port.OutIP,
		Port: int(port.OutPort),
	})

	if err != nil && isPermissionDenied(err) {
		// fall back to vmnetd
		l, err := listenTCPVmnet(port.OutIP, port.OutPort)
		return l, err
	}
	return l, err
}

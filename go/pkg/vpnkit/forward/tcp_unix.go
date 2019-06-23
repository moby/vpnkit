//+build !windows

package forward

import (
	"github.com/moby/vpnkit/go/pkg/vpnkit"
	"net"
)

func listenTCP(port vpnkit.Port) (*net.TCPListener, error) {
	if port.OutPort > 1024 {
		return net.ListenTCP("tcp", &net.TCPAddr{
			IP:   port.OutIP,
			Port: int(port.OutPort),
		})
	}
	return listenTCPVmnet(port.OutIP, port.OutPort)
}

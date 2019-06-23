package forward

import (
	"github.com/moby/vpnkit/go/pkg/vpnkit"
	"net"
)

func listenTCP(port vpnkit.Port) (*net.TCPListener, error) {
	return net.ListenTCP("tcp", &net.TCPAddr{
		IP:   port.OutIP,
		Port: int(port.OutPort),
	})
}

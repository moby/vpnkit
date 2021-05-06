package forward

import (
	"net"

	"github.com/moby/vpnkit/go/pkg/vpnkit"
)

func listenTCP(port vpnkit.Port) (net.Listener, bool, error) {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   port.OutIP,
		Port: int(port.OutPort),
	})
	return l, false, err
}

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
	return l, false, err
}

func closeTCP(port vpnkit.Port, _ bool, l *net.TCPListener) error {
	return l.Close()
}

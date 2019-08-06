package forward

import (
	"net"

	"github.com/moby/vpnkit/go/pkg/vpnkit"
)

func listenUDP(port vpnkit.Port) (*net.UDPConn, error) {
	return net.ListenUDP("udp", &net.UDPAddr{
		IP:   port.OutIP,
		Port: int(port.OutPort),
	})
}

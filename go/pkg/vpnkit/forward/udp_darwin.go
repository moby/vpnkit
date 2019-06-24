//+build !windows

package forward

import (
	"github.com/moby/vpnkit/go/pkg/vpnkit"
	"net"
)

func listenUDP(port vpnkit.Port) (*net.UDPConn, error) {
	if port.OutPort > 1024 {
		return net.ListenUDP("udp", &net.UDPAddr{
			IP:   port.OutIP,
			Port: int(port.OutPort),
		})
	}
	return listenUDPVmnet(port.OutIP, port.OutPort)
}

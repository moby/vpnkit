//+build !windows

package forward

import (
	"net"

	"github.com/moby/vpnkit/go/pkg/libproxy"
	"github.com/moby/vpnkit/go/pkg/vpnkit"
)

func listenUDP(port vpnkit.Port) (libproxy.UDPListener, error) {
	l, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   port.OutIP,
		Port: int(port.OutPort),
	})
	if err != nil && isPermissionDenied(err) {
		// fall back to vmnetd
		l, err := listenUDPVmnet(port.OutIP, port.OutPort)
		if err != nil {
			return nil, err
		}
		return l, nil
	}
	return l, err
}

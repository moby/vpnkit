//+build !windows

package forward

import (
	"net"

	"github.com/moby/vpnkit/go/pkg/libproxy"
	"github.com/moby/vpnkit/go/pkg/vpnkit"
)

func listenUDP(port vpnkit.Port) (libproxy.UDPListener, error) {
	if port.OutPort > 1024 {
		return net.ListenUDP("udp", &net.UDPAddr{
			IP:   port.OutIP,
			Port: int(port.OutPort),
		})
	}
	l, err := listenUDPVmnet(port.OutIP, port.OutPort)
	if err != nil {
		return nil, err
	}
	return &wrappedCloser{port, l}, nil
}

type wrappedCloser struct {
	port vpnkit.Port
	l    *net.UDPConn
}

func (w *wrappedCloser) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	return w.l.ReadFromUDP(b)
}

func (w *wrappedCloser) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	return w.l.WriteToUDP(b, addr)
}

func (w *wrappedCloser) Close() error {
	return closeUDPVmnet(w.port.OutIP, w.port.OutPort, w.l)
}

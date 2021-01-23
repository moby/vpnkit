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
		return &wrappedCloser{port, l}, nil
	}
	return l, err
}

type wrappedCloser struct {
	port vpnkit.Port
	l    libproxy.UDPListener
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

func (w *wrappedCloser) LocalAddr() net.Addr {
	return w.l.LocalAddr()
}

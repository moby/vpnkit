package forward

import (
	"net"

	"github.com/moby/vpnkit/go/pkg/libproxy"
	"github.com/moby/vpnkit/go/pkg/vpnkit"
)

// Listen on TCP sockets and forward to a remote multiplexer.

// TCPNetwork specifies common parameters for TCP-based port forwards.
type TCPNetwork struct{}

func (t TCPNetwork) listen(port vpnkit.Port) (listener, error) {
	l, vmnetd, err := listenTCP(port)
	if err != nil {
		return nil, err
	}
	if port.OutPort == 0 {
		addr, ok := l.Addr().(*net.TCPAddr)
		if ok {
			port.OutPort = uint16(addr.Port)
		}
	}
	wrapped := &tcpListener{
		l:      l,
		vmnetd: vmnetd,
		p:      port,
	}
	return wrapped, nil
}

type tcpListener struct {
	l      *net.TCPListener
	vmnetd bool
	p      vpnkit.Port
}

func (l *tcpListener) accept() (libproxy.Conn, error) {
	return l.l.AcceptTCP()
}

func (l *tcpListener) close() error {
	return closeTCP(l.p, l.vmnetd, l.l)
}

func makeTCP(c common, n TCPNetwork) (Forward, error) {
	return makeStream(c, n)
}

func (l *tcpListener) port() vpnkit.Port {
	return l.p
}

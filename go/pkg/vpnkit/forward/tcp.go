package forward

import (
	"net"

	"github.com/moby/vpnkit/go/pkg/libproxy"
	"github.com/moby/vpnkit/go/pkg/vpnkit"
)

// Listen on TCP sockets and forward to a remote multiplexer.

type tcpNetwork struct{}

func (t *tcpNetwork) listen(port vpnkit.Port) (listener, error) {
	l, err := listenTCP(port)
	if err != nil {
		return nil, err
	}
	wrapped := &tcpListener{
		l : l,
		port: port,
	}
	return wrapped, nil
}

type tcpListener struct {
	l *net.TCPListener
	port vpnkit.Port
}

func (l *tcpListener) accept() (libproxy.Conn, error) {
	return l.l.AcceptTCP()
}

func (l *tcpListener) close() error {
	return closeTCP(l.port, l.l)
}

func makeTCP(c common) (Forward, error) {
	return makeStream(c, &tcpNetwork{})
}

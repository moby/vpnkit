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
	wrapped := tcpListener(*l)
	return &wrapped, nil
}

type tcpListener net.TCPListener

func (l tcpListener) accept() (libproxy.Conn, error) {
	t := net.TCPListener(l)
	return t.AcceptTCP()
}

func (l tcpListener) close() error {
	t := net.TCPListener(l)
	return t.Close()
}

func makeTCP(c common) (Forward, error) {
	return makeStream(c, &tcpNetwork{})
}

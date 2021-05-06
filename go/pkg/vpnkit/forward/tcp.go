package forward

import (
	"errors"
	"net"

	"github.com/moby/vpnkit/go/pkg/libproxy"
	"github.com/moby/vpnkit/go/pkg/vpnkit"
)

// Listen on TCP sockets and forward to a remote multiplexer.

// TCPNetwork specifies common parameters for TCP-based port forwards.
type TCPNetwork struct{}

func (t TCPNetwork) listen(port vpnkit.Port) (listener, error) {
	l, err := listenTCP(port)
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
		l: l,
		p: port,
	}
	return wrapped, nil
}

type tcpListener struct {
	l net.Listener
	p vpnkit.Port
}

func (l *tcpListener) accept() (libproxy.Conn, error) {
	c, err := l.l.Accept()
	if err != nil {
		return nil, err
	}
	c2, ok := c.(libproxy.Conn)
	if !ok {
		return nil, errors.New("accepted connection is not a libproxy.Conn")
	}
	return c2, nil
}

func (l *tcpListener) close() error {
	return l.l.Close()
}

func makeTCP(c common, n TCPNetwork) (Forward, error) {
	return makeStream(c, n)
}

func (l *tcpListener) port() vpnkit.Port {
	return l.p
}

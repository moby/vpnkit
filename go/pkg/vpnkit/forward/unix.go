package forward

import (
	"net"

	"github.com/moby/vpnkit/go/pkg/libproxy"
	"github.com/moby/vpnkit/go/pkg/vpnkit"
)

// Listen on Unix sockets and forward to a remote multiplexer.

type unixNetwork struct{}

func (t *unixNetwork) listen(port vpnkit.Port) (listener, error) {
	l, err := net.ListenUnix("unix", &net.UnixAddr{
		Net:  "unix",
		Name: port.OutPath,
	})
	if err != nil {
		return nil, err
	}
	wrapped := unixListener(*l)
	return &wrapped, nil
}

type unixListener net.UnixListener

func (l unixListener) accept() (libproxy.Conn, error) {
	t := net.UnixListener(l)
	return t.AcceptUnix()
}

func (l unixListener) close() error {
	t := net.UnixListener(l)
	return t.Close()
}

func makeUnix(c common) (Forward, error) {
	return makeStream(c, &unixNetwork{})
}

package forward

import (
	"github.com/moby/vpnkit/go/pkg/libproxy"
	"github.com/moby/vpnkit/go/pkg/vpnkit"
	"github.com/pkg/errors"
	"net"
	"os"
)

// Listen on Unix sockets and forward to a remote multiplexer.

type unixNetwork struct{}

func removeExistingSocket(path string) error {
	// Only remove a path if it is a Unix domain socket. Don't remove arbitrary files
	// by accident.
	if !isSafeToRemove(path) {
		return errors.New("refusing to remove path " + path)
	}
	if err := os.Remove(path); err != nil {
		return errors.Wrap(err, "removing "+path)
	}
	return nil
}

func (t *unixNetwork) listen(port vpnkit.Port) (listener, error) {
	if err := removeExistingSocket(port.OutPath); err != nil {
		return nil, err
	}
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

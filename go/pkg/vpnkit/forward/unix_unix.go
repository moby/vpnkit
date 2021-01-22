// +build !windows

package forward

import (
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/moby/vpnkit/go/pkg/libproxy"
	"github.com/moby/vpnkit/go/pkg/vpnkit"
	"github.com/pkg/errors"
)

// UnixNetwork specifies common parameters for Unix domain socket forwards.
type UnixNetwork struct{}

func (t UnixNetwork) listen(port vpnkit.Port) (listener, error) {
	if err := removeExistingSocket(port.OutPath); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(port.OutPath), 0755); err != nil && !os.IsExist(err) {
		return nil, errors.Wrapf(err, "making %s", filepath.Dir(port.OutPath))
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{
		Net:  "unix",
		Name: port.OutPath,
	})
	if err != nil {
		return nil, err
	}
	wrapped := unixListener{l, port}
	return &wrapped, nil
}

type unixListener struct {
	l *net.UnixListener
	p vpnkit.Port
}

func (l unixListener) accept() (libproxy.Conn, error) {
	return l.l.AcceptUnix()
}

func (l unixListener) close() error {
	return l.l.Close()
}

func (l unixListener) port() vpnkit.Port {
	return l.p
}

func makeUnix(c common, n UnixNetwork) (Forward, error) {
	return makeStream(c, n)
}

func removeExistingSocket(path string) error {
	// Only remove a path if it is a Unix domain socket. Don't remove arbitrary files
	// by accident.
	if !isSafeToRemove(path) {
		return errors.New("refusing to remove path " + path)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return errors.Wrap(err, "removing "+path)
	}
	return nil
}

// isSaveToRemove returns true if the path references a Unix domain socket or named pipe
// or if the path doesn't exist at all
func isSafeToRemove(path string) bool {
	var statT syscall.Stat_t
	if err := syscall.Stat(path, &statT); err != nil {
		return os.IsNotExist(err)
	}
	return statT.Mode&syscall.S_IFMT == syscall.S_IFSOCK
}

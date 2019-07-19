package forward

import (
	"errors"
	"net"

	"github.com/Microsoft/go-winio"
	"github.com/moby/vpnkit/go/pkg/libproxy"
	"github.com/moby/vpnkit/go/pkg/vpnkit"
)

// UnixNetwork specifies common parameters for Windows named pipe forwards.
type UnixNetwork struct{}

func (t UnixNetwork) listen(port vpnkit.Port) (listener, error) {
	l, err := winio.ListenPipe(port.OutPath, &winio.PipeConfig{
		MessageMode:      true,  // Use message mode so that CloseWrite() is supported
		InputBufferSize:  65536, // Use 64KB buffers to improve performance
		OutputBufferSize: 65536,
	})
	if err != nil {
		return nil, err
	}
	wrapped := unixListener{l}
	return &wrapped, nil
}

type unixListener struct {
	l net.Listener
}

func (l unixListener) accept() (libproxy.Conn, error) {
	c, err := l.l.Accept()
	if err != nil {
		return nil, err
	}
	conn, ok := c.(libproxy.Conn)
	if !ok {
		return nil, errors.New("Named pipe connection does not support WriteClose")
	}
	return conn, nil
}

func (l unixListener) close() error {
	return l.l.Close()
}

func makeUnix(c common, n UnixNetwork) (Forward, error) {
	return makeStream(c, n)
}

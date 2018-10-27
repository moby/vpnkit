package vpnkit

import (
	"io"

	"github.com/linuxkit/virtsock/pkg/vsock"
)

func (d *Dialer) connectTransport() (io.ReadWriteCloser, error) {
	port := d.Port
	if port == 0 {
		port = DefaultVsockPort
	}
	// 3 is the first VM
	return vsock.Dial(3, port)
}

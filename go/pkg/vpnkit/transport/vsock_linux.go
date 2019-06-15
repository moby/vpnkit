package transport

import (
	"context"
	"net"
	"strconv"

	"github.com/linuxkit/virtsock/pkg/vsock"
	"github.com/pkg/errors"
)

func NewVsockTransport() Transport {
	if hvsockSupported() {
		return &hvs{}
	}
	return &vs{}
}

type vs struct {
}

func (_ *vs) Dial(_ context.Context, path string) (net.Conn, error) {
	port, err := parsePort(path)
	if err != nil {
		return nil, err
	}
	return vsock.Dial(vsock.CIDHost, uint32(port))
}

func (_ *vs) Listen(path string) (net.Listener, error) {
	port, err := parsePort(path)
	if err != nil {
		return nil, err
	}
	return vsock.Listen(vsock.CIDAny, uint32(port))
}

func parsePort(path string) (uint32, error) {
	port, err := strconv.ParseUint(path, 10, 32)
	if err != nil {
		return 0, errors.Wrapf(err, "on Linux the vpnkit control client needs an AF_VSOCK port number")
	}
	return uint32(port), err
}

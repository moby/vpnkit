package transport

import (
	"context"
	"net"

	"github.com/linuxkit/virtsock/pkg/vsock"
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
	addr, err := parseAddr(path)
	if err != nil {
		return nil, err
	}
	cid := uint32(vsock.CIDHost)
	if addr.cid != vsock.CIDAny {
		cid = addr.cid
	}
	return vsock.Dial(cid, addr.port)
}

func (_ *vs) Listen(path string) (net.Listener, error) {
	addr, err := parseAddr(path)
	if err != nil {
		return nil, err
	}
	return vsock.Listen(vsock.CIDAny, addr.port)
}

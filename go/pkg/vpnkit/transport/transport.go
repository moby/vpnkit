package transport

import (
	"context"
	"net"
)

// Transport carries the HTTP port control messages.
type Transport interface {
	Dial(_ context.Context, path string) (net.Conn, error)
	Listen(path string) (net.Listener, error)
}

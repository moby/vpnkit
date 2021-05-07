package transport

import (
	"context"
	"net"
)

// Transport carries the HTTP port control messages.
type Transport interface {
	Dial(_ context.Context, path string) (net.Conn, error)
	Listen(path string) (net.Listener, error)
	String() string
	// SetSecurityDescriptor for Windows named pipes in SDDL format, see
	// https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language
	// For example to allow Administrator and System: "D:P(A;;GA;;;BA)(A;;GA;;;SY)".
	SetSecurityDescriptor(sddl string)
}

// Choose a transport based on a path.
func Choose(path string) Transport {
	_, err := parseAddr(path)
	if err == nil {
		return NewVsockTransport()
	}
	return NewUnixTransport()
}

package transport

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"syscall"

	"github.com/linuxkit/virtsock/pkg/hvsock"
	"github.com/pkg/errors"
)

// hvsockSupported returns true if the kernel has been patched to use AF_HVSOCK.
func hvsockSupported() bool {
	// Try opening  a hvsockAF socket. If it works we are on older, i.e. 4.9.x kernels.
	// 4.11 defines AF_SMC as 43 but it doesn't support protocol 1 so the
	// socket() call should fail.
	fd, err := syscall.Socket(43, syscall.SOCK_STREAM, 1)
	if err != nil {
		return false
	}
	if err := syscall.Close(fd); err != nil {
		log.Printf("cannot close AF_HVSOCK socket: %v", err)
	}
	return true
}

type hvs struct {
}

func (_ *hvs) Dial(_ context.Context, path string) (net.Conn, error) {
	svcid, err := parseGUID(path)
	if err != nil {
		return nil, err
	}
	return hvsock.Dial(hvsock.HypervAddr{VMID: hvsock.GUIDParent, ServiceID: svcid})
}

func (_ *hvs) Listen(path string) (net.Listener, error) {
	svcid, err := parseGUID(path)
	if err != nil {
		return nil, err
	}
	return hvsock.Listen(hvsock.Addr{VMID: hvsock.GUIDWildcard, ServiceID: svcid})
}

func parseGUID(path string) (hvsock.GUID, error) {
	port, err := strconv.ParseUint(path, 10, 32)
	if err != nil {
		return hvsock.GUIDZero, errors.Wrapf(err, "expected an AF_VSOCK port number")
	}
	serviceID := fmt.Sprintf("%08x-FACB-11E6-BD58-64006A7986D3", port)
	return hvsock.GUIDFromString(serviceID)
}

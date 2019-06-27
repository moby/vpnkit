package transport

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
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
	vmid, svcid, err := parsePort(path)
	if err != nil {
		return nil, err
	}
	return hvsock.Dial(hvsock.HypervAddr{VMID: vmid, ServiceID: svcid})
}

func (_ *hvs) Listen(path string) (net.Listener, error) {
	_, svcid, err := parsePort(path)
	if err != nil {
		return nil, err
	}
	return hvsock.Listen(hvsock.Addr{VMID: hvsock.GUIDWildcard, ServiceID: svcid})
}

func parsePort(path string) (hvsock.GUID, hvsock.GUID, error) {
	vmId := hvsock.GUIDZero
	svcId := hvsock.GUIDZero
	bits := strings.SplitN(path, "/", 2)
	if len(bits) != 1 && len(bits) != 2 {
		return vmId, svcId, errors.New("expected either <port> or <vmid>/<port>")
	}
	var err error
	if len(bits) == 2 {
		vmId, err = hvsock.GUIDFromString(bits[0])
		if err != nil {
			return vmId, svcId, errors.New("unable to parse Hyper-V VM ID " + bits[0])
		}
		path = bits[1]
	}
	port, err := strconv.ParseUint(path, 10, 32)
	if err != nil {
		return vmId, svcId, errors.New("expected an AF_VSOCK port number")
	}
	serviceID := fmt.Sprintf("%08x-FACB-11E6-BD58-64006A7986D3", port)
	svcId, err = hvsock.GUIDFromString(serviceID)
	return vmId, svcId, err
}

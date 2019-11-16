package transport

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/linuxkit/virtsock/pkg/hvsock"
	"github.com/linuxkit/virtsock/pkg/vsock"
	"github.com/pkg/errors"
)

type hvs struct {
}

func (_ *hvs) Dial(_ context.Context, path string) (net.Conn, error) {
	addr, err := parseAddr(path)
	if err != nil {
		return nil, err
	}
	return hvsock.Dial(hvsock.Addr{VMID: addr.vmID, ServiceID: addr.svcID})
}

func (_ *hvs) Listen(path string) (net.Listener, error) {
	addr, err := parseAddr(path)
	if err != nil {
		return nil, err
	}
	return hvsock.Listen(hvsock.Addr{VMID: hvsock.GUIDWildcard, ServiceID: addr.svcID})
}

func (_ *hvs) String() string {
	return "Windows AF_HYPERV"
}

// addr is a union of hvsock.HypervAddr and vsock.VsockAddr addresses
type addr struct {
	vmID  hvsock.GUID
	svcID hvsock.GUID
	cid   uint32
	port  uint32
}

func parseAddr(path string) (*addr, error) {
	// The string has an optional <vm>/ prefix
	bits := strings.SplitN(path, "/", 2)
	// The last thing on the string is always the port number
	portString := bits[0]
	if len(bits) == 2 {
		portString = bits[1]
	}
	addr := &addr{
		vmID:  hvsock.GUIDZero,
		svcID: hvsock.GUIDZero,
		cid:   vsock.CIDAny,
		port:  0,
	}
	// Maybe the port string is a GUID?
	svcID, err := hvsock.GUIDFromString(portString)
	if err == nil {
		addr.svcID = svcID
	} else {
		port, err := strconv.ParseUint(portString, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("cannot parse %s as service GUID or AF_VSOCK port", portString)
		}
		addr.port = uint32(port)
		serviceID := fmt.Sprintf("%08x-FACB-11E6-BD58-64006A7986D3", port)
		svcID, err := hvsock.GUIDFromString(serviceID)
		if err != nil {
			// should never happen
			return nil, errors.New("cannot create service ID from AF_VSOCK port number")
		}
		addr.svcID = svcID
	}

	// Is there a <vm>/ prefix?
	if len(bits) == 1 {
		return addr, nil
	}
	vmID, err := hvsock.GUIDFromString(bits[0])
	if err == nil {
		addr.vmID = vmID
		return addr, nil
	}
	// Maybe it's an integer
	cid, err := strconv.ParseUint(bits[0], 10, 32)
	if err != nil {
		return nil, errors.New("unable to parse the <vm>/ as either a GUID or AF_VSOCK port number")
	}
	addr.cid = uint32(cid)
	return addr, nil
}

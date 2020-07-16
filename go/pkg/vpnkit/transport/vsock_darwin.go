package transport

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/linuxkit/virtsock/pkg/vsock"
	"github.com/pkg/errors"
)

func NewVsockTransport() Transport {
	return &vs{}
}

type vs struct {
}

const CIDVM0 = 3

func (_ *vs) Dial(_ context.Context, path string) (net.Conn, error) {
	addr, err := parseAddr(path)
	if err != nil {
		return nil, err
	}
	addr.cid = CIDVM0
	p, err := toPath(addr)
	if err != nil {
		return nil, err
	}
	return net.Dial("unix", p)
}

func (_ *vs) Listen(path string) (net.Listener, error) {
	addr, err := parseAddr(path)
	if err != nil {
		return nil, err
	}
	addr.cid = vsock.CIDHost
	p, err := toPath(addr)
	if err != nil {
		return nil, err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return nil, errors.Wrap(err, "removing "+p)
	}
	return net.Listen("unix", p)
}

func (_ *vs) String() string {
	return "Hyperkit AF_VSOCK"
}

func toPath(a *addr) (string, error) {
	user, err := user.Current()
	if err != nil {
		return "", errors.New("Unable to determine current user")
	}
	unshortened := filepath.Join(user.HomeDir, "Library", "Containers", "com.docker.docker", "Data", "vms", "0", fmt.Sprintf("%08x.%08x", a.cid, a.port))
	return shortenUnixSocketPath(unshortened)
}

// shortenUnixSocketPath returns a path shortened so it fits inside a socket address.
// This is needed because paths can be much larger than the space available inside a
// socket address.
func shortenUnixSocketPath(path string) (string, error) {
	if len(path) <= maxDarwinSocketPathLen {
		return path, nil
	}
	// absolute path is too long, attempt to use a relative path
	p, err := relative(path)
	if err != nil {
		return "", err
	}

	if len(p) > maxDarwinSocketPathLen {
		return "", fmt.Errorf("absolute and relative socket path %s longer than %d characters", p, maxDarwinSocketPathLen)
	}
	return p, nil
}

func relative(p string) (string, error) {
	// Assume the parent directory exists already but the child (the socket)
	// hasn't been created.
	path2, err := filepath.EvalSymlinks(filepath.Dir(p))
	if err != nil {
		return "", err
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir2, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(dir2, path2)
	if err != nil {
		return "", err
	}
	return filepath.Join(rel, filepath.Base(p)), nil
}

const maxDarwinSocketPathLen = 104

type addr struct {
	cid  uint32
	port uint32
}

func parseAddr(path string) (*addr, error) {
	port, err := strconv.ParseUint(path, 10, 32)
	if err != nil {
		return nil, errors.Wrapf(err, "AF_VSOCK port number is an integer")
	}
	return &addr{
		port: uint32(port),
	}, nil
}

// +build !windows

package transport

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

func NewUnixTransport() Transport {
	return &unix{}
}

type unix struct {
}

func (_ *unix) Dial(_ context.Context, path string) (net.Conn, error) {
	shorter, err := shortenUnixSocketPath(path)
	if err != nil {
		return nil, err
	}
	return net.Dial("unix", shorter)
}

func (_ *unix) Listen(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, errors.Wrap(err, "removing "+path)
	}
	shorter, err := shortenUnixSocketPath(path)
	if err != nil {
		return nil, err
	}
	return net.Listen("unix", shorter)
}

func (_ *unix) String() string {
	return "Unix domain socket"
}

func (_ *unix) SetSecurityDescriptor(string) {}

// shortenUnixSocketPath returns a path shortened so it fits inside a socket address.
// This is needed because paths can be much larger than the space available inside a
// socket address.
func shortenUnixSocketPath(path string) (string, error) {
	if len(path) <= maxUnixSocketPathLen {
		return path, nil
	}
	// absolute path is too long, attempt to use a relative path
	p, err := relative(path)
	if err != nil {
		return "", err
	}

	if len(p) > maxUnixSocketPathLen {
		return "", fmt.Errorf("absolute and relative socket path %s longer than %d characters", p, maxUnixSocketPathLen)
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

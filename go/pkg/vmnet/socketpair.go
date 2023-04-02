package vmnet

import (
	"syscall"

	"github.com/pkg/errors"
)

func socketpair() ([2]int, error) {
	invalid := [2]int{-1, -1}
	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return invalid, errors.Wrap(err, "creating SOCK_DGRAM socketpair for ethernet")
	}
	defer func() {
		if err == nil {
			return
		}
		for _, fd := range fds {
			_ = syscall.Close(fd)
		}
	}()

	for _, fd := range fds {
		maxLength := 1048576
		if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, maxLength); err != nil {
			return invalid, errors.Wrap(err, "setting SO_RCVBUF")
		}
		if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, maxLength); err != nil {
			return invalid, errors.Wrap(err, "setting SO_SNDBUF")
		}
	}
	return fds, nil
}

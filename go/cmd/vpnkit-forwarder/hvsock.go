package main

import (
	"log"
	"syscall"
)

// HvsockSupported returns true if the kernel has been patched to use AF_HVSOCK.
func HvsockSupported() bool {
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

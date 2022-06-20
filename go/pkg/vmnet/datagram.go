package vmnet

/*
// FIXME: Needed because we call C.send. Perhaps we could use syscall instead?
#include <stdlib.h>
#include <sys/socket.h>

*/
import "C"

import (
	"syscall"

	"github.com/pkg/errors"
)

// Datagram sends and receives ethernet frames via send/recv over a SOCK_DGRAM fd.
type Datagram struct {
	Fd   int // Underlying SOCK_DGRAM file descriptor.
	pcap *PcapWriter
}

func (e Datagram) Recv(buf []byte) (int, error) {
	num, _, err := syscall.Recvfrom(e.Fd, buf, 0)
	if e.pcap != nil {
		if err := e.pcap.Write(buf[0:num]); err != nil {
			return 0, errors.Wrap(err, "writing to pcap")
		}
	}
	return num, err
}

func (e Datagram) Send(packet []byte) (int, error) {
	if e.pcap != nil {
		if err := e.pcap.Write(packet); err != nil {
			return 0, errors.Wrap(err, "writing to pcap")
		}
	}
	result, err := C.send(C.int(e.Fd), C.CBytes(packet), C.size_t(len(packet)), 0)
	if result == -1 {
		return 0, err
	}
	return len(packet), nil
}

func (e Datagram) Close() error {
	return syscall.Close(e.Fd)
}

var _ sendReceiver = Datagram{}

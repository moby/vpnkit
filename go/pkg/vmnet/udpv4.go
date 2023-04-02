package vmnet

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/pkg/errors"
)

// Udpv4 is a Udpv4 frame
type Udpv4 struct {
	Src      uint16
	Dst      uint16
	Data     []byte
	Checksum uint16
}

// NewUdpv4 constructs a Udpv4 frame
func NewUdpv4(ipv4 *Ipv4, Dst, Src uint16, Data []byte) *Udpv4 {
	Checksum := uint16(0)
	return &Udpv4{Dst, Src, Data, Checksum}
}

// ParseUdpv4 parses a Udpv4 packet
func ParseUdpv4(packet []byte) (*Udpv4, error) {
	if len(packet) < 8 {
		return nil, errors.New("UDPv4 is too short")
	}
	Src := uint16(packet[0])<<8 + uint16(packet[1])
	Dst := uint16(packet[2])<<8 + uint16(packet[3])
	Checksum := uint16(packet[6])<<8 + uint16(packet[7])
	Data := packet[8:]
	return &Udpv4{Src, Dst, Data, Checksum}, nil
}

// Write marshalls a Udpv4 frame
func (u *Udpv4) Write(w io.Writer) error {
	if err := binary.Write(w, binary.BigEndian, u.Src); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, u.Dst); err != nil {
		return err
	}
	length := uint16(8 + len(u.Data))
	if err := binary.Write(w, binary.BigEndian, length); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, u.Checksum); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, u.Data); err != nil {
		return err
	}
	return nil
}

// Bytes returns the marshalled Udpv4 frame
func (u *Udpv4) Bytes() []byte {
	buf := bytes.NewBufferString("")
	if err := u.Write(buf); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

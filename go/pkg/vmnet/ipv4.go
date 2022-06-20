package vmnet

import (
	"net"

	"github.com/pkg/errors"
)

// Ipv4 is an IPv4 frame
type Ipv4 struct {
	Dst      net.IP
	Src      net.IP
	Data     []byte
	Checksum uint16
}

// NewIpv4 constructs a new empty IPv4 packet
func NewIpv4(Dst, Src net.IP) *Ipv4 {
	Checksum := uint16(0)
	Data := make([]byte, 0)
	return &Ipv4{Dst, Src, Data, Checksum}
}

// ParseIpv4 parses an IP packet
func ParseIpv4(packet []byte) (*Ipv4, error) {
	if len(packet) < 20 {
		return nil, errors.New("IPv4 packet too small")
	}
	ihl := int((packet[0] & 0xf) * 4) // in octets
	if len(packet) < ihl {
		return nil, errors.New("IPv4 packet too small")
	}
	Dst := packet[12:16]
	Src := packet[16:20]
	Data := packet[ihl:]
	Checksum := uint16(0) // assume offload
	return &Ipv4{Dst, Src, Data, Checksum}, nil
}

func (i *Ipv4) setData(data []byte) {
	i.Data = data
	i.Checksum = uint16(0) // as if we were using offload
}

// HeaderBytes returns the marshalled form of the IPv4 header
func (i *Ipv4) HeaderBytes() []byte {
	len := len(i.Data) + 20
	length := [2]byte{byte(len >> 8), byte(len & 0xff)}
	checksum := [2]byte{byte(i.Checksum >> 8), byte(i.Checksum & 0xff)}
	return []byte{
		0x45,                 // version + IHL
		0x00,                 // DSCP + ECN
		length[0], length[1], // total length
		0x7f, 0x61, // Identification
		0x00, 0x00, // Flags + Fragment offset
		0x40, // TTL
		0x11, // Protocol
		checksum[0], checksum[1],
		0x00, 0x00, 0x00, 0x00, // source
		0xff, 0xff, 0xff, 0xff, // destination
	}
}

// Bytes returns the marshalled IPv4 packet
func (i *Ipv4) Bytes() []byte {
	header := i.HeaderBytes()
	return append(header, i.Data...)
}

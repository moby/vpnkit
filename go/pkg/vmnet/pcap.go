package vmnet

import (
	"encoding/binary"
	"io"
	"sync"
	"time"
)

// PcapWriter writes pcap-formatted packet streams. The results can be analysed with tcpdump/wireshark.
type PcapWriter struct {
	w       io.Writer
	snaplen uint32
	m       sync.Mutex
}

// NewPcapWriter creates a PcapWriter and writes the initial header
func NewPcapWriter(w io.Writer) (*PcapWriter, error) {
	magic := uint32(0xa1b2c3d4)
	major := uint16(2)
	minor := uint16(4)
	thiszone := uint32(0)   // GMT to local correction
	sigfigs := uint32(0)    // accuracy of local timestamps
	snaplen := uint32(1500) // max length of captured packets, in octets
	network := uint32(1)    // ethernet
	if err := binary.Write(w, binary.LittleEndian, magic); err != nil {
		return nil, err
	}
	if err := binary.Write(w, binary.LittleEndian, major); err != nil {
		return nil, err
	}
	if err := binary.Write(w, binary.LittleEndian, minor); err != nil {
		return nil, err
	}
	if err := binary.Write(w, binary.LittleEndian, thiszone); err != nil {
		return nil, err
	}
	if err := binary.Write(w, binary.LittleEndian, sigfigs); err != nil {
		return nil, err
	}
	if err := binary.Write(w, binary.LittleEndian, snaplen); err != nil {
		return nil, err
	}
	if err := binary.Write(w, binary.LittleEndian, network); err != nil {
		return nil, err
	}
	return &PcapWriter{
		w:       w,
		snaplen: snaplen,
	}, nil
}

// Write appends a packet with a pcap-format header
func (p *PcapWriter) Write(packet []byte) error {
	p.m.Lock()
	defer p.m.Unlock()
	stamp := time.Now()
	s := uint32(stamp.Second())
	us := uint32(stamp.Nanosecond() / 1000)
	actualLen := uint32(len(packet))
	if err := binary.Write(p.w, binary.LittleEndian, s); err != nil {
		return err
	}
	if err := binary.Write(p.w, binary.LittleEndian, us); err != nil {
		return err
	}
	toWrite := packet[:]
	if actualLen > p.snaplen {
		toWrite = toWrite[0:p.snaplen]
	}
	caplen := uint32(len(toWrite))
	if err := binary.Write(p.w, binary.LittleEndian, caplen); err != nil {
		return err
	}
	if err := binary.Write(p.w, binary.LittleEndian, actualLen); err != nil {
		return err
	}

	if err := binary.Write(p.w, binary.LittleEndian, toWrite); err != nil {
		return err
	}
	return nil
}

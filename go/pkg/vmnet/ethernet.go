package vmnet

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"

	"github.com/pkg/errors"
)

// EthernetFrame is an ethernet frame
type EthernetFrame struct {
	Dst  net.HardwareAddr
	Src  net.HardwareAddr
	Type uint16
	Data []byte
}

// NewEthernetFrame constructs an Ethernet frame
func NewEthernetFrame(Dst, Src net.HardwareAddr, Type uint16) *EthernetFrame {
	Data := make([]byte, 0)
	return &EthernetFrame{Dst, Src, Type, Data}
}

func (e *EthernetFrame) setData(data []byte) {
	e.Data = data
}

// Write marshals an Ethernet frame
func (e *EthernetFrame) Write(w io.Writer) error {
	if err := binary.Write(w, binary.BigEndian, e.Dst); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, e.Src); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, e.Type); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, e.Data); err != nil {
		return err
	}
	return nil
}

// ParseEthernetFrame parses the ethernet frame
func ParseEthernetFrame(frame []byte) (*EthernetFrame, error) {
	if len(frame) < (6 + 6 + 2) {
		return nil, errors.New("Ethernet frame is too small")
	}
	Dst := frame[0:6]
	Src := frame[6:12]
	Type := uint16(frame[12])<<8 + uint16(frame[13])
	Data := frame[14:]
	return &EthernetFrame{Dst, Src, Type, Data}, nil
}

// Bytes returns the marshalled ethernet frame
func (e *EthernetFrame) Bytes() []byte {
	buf := bytes.NewBufferString("")
	if err := e.Write(buf); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

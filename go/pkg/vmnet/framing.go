package vmnet

import (
	"encoding/binary"
	"io"
)

// Messages sent to vpnkit can either be
// - fixed-size, no length prefix
// - variable-length, with a length prefix

// fixedSizeSendReceiver sends and receives fixed-size control messages with no length prefix.
type fixedSizeSendReceiver struct {
	rw io.ReadWriter
}

var _ sendReceiver = fixedSizeSendReceiver{}

func (f fixedSizeSendReceiver) Recv(buf []byte) (int, error) {
	return io.ReadFull(f.rw, buf)
}

func (f fixedSizeSendReceiver) Send(buf []byte) (int, error) {
	return f.rw.Write(buf)
}

// lengthPrefixer sends and receives variable-length control messages with a length prefix.
type lengthPrefixer struct {
	rw io.ReadWriter
}

var _ sendReceiver = lengthPrefixer{}

func (e lengthPrefixer) Recv(buf []byte) (int, error) {
	var len uint16
	if err := binary.Read(e.rw, binary.LittleEndian, &len); err != nil {
		return 0, err
	}
	if err := binary.Read(e.rw, binary.LittleEndian, &buf); err != nil {
		return 0, err
	}
	return int(len), nil
}

func (e lengthPrefixer) Send(packet []byte) (int, error) {
	len := uint16(len(packet))
	if err := binary.Write(e.rw, binary.LittleEndian, len); err != nil {
		return 0, err
	}
	if err := binary.Write(e.rw, binary.LittleEndian, packet); err != nil {
		return 0, err
	}
	return int(len), nil
}

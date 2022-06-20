package vmnet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// vpnkit internal protocol requests and responses

func negotiate(sr sendReceiver) (*InitMessage, error) {
	m := defaultInitMessage()
	if err := m.Send(sr); err != nil {
		return nil, err
	}
	return readInitMessage(sr)
}

// InitMessage is used for the initial version exchange
type InitMessage struct {
	magic   [5]byte
	version uint32
	commit  [40]byte
}

const sizeof_InitMessage = 5 + 4 + 40

// String returns a human-readable string.
func (m *InitMessage) String() string {
	return fmt.Sprintf("magic=%v version=%d commit=%v", m.magic, m.version, m.commit)
}

// defaultInitMessage is the init message we will send to vpnkit
func defaultInitMessage() *InitMessage {
	magic := [5]byte{'V', 'M', 'N', '3', 'T'}
	version := uint32(22)
	var commit [40]byte
	copy(commit[:], []byte("0123456789012345678901234567890123456789"))
	return &InitMessage{magic, version, commit}
}

// Write marshals an init message to a connection
func (m *InitMessage) Send(sr sendReceiver) error {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, m.magic); err != nil {
		return err
	}
	if err := binary.Write(&buf, binary.LittleEndian, m.version); err != nil {
		return err
	}
	if err := binary.Write(&buf, binary.LittleEndian, m.commit); err != nil {
		return err
	}
	_, err := sr.Send(buf.Bytes())
	return err
}

// readInitMessage unmarshals an init message from a connection
func readInitMessage(sr sendReceiver) (*InitMessage, error) {
	m := defaultInitMessage()
	bs := make([]byte, sizeof_InitMessage)
	n, err := sr.Recv(bs)
	if err != nil {
		return nil, err
	}
	br := bytes.NewReader(bs[0:n])
	if err := binary.Read(br, binary.LittleEndian, &m.magic); err != nil {
		return nil, err
	}
	if err := binary.Read(br, binary.LittleEndian, &m.version); err != nil {
		return nil, err
	}
	log.Printf("version = %d", m.version)
	if err := binary.Read(br, binary.LittleEndian, &m.commit); err != nil {
		return nil, err
	}
	return m, nil
}

// EthernetRequest requests the creation of a network connection with a given
// uuid and optional IP
type EthernetRequest struct {
	uuid uuid.UUID
	ip   net.IP
}

// NewEthernetRequest requests an Ethernet connection
func NewEthernetRequest(uuid uuid.UUID, ip net.IP) *EthernetRequest {
	return &EthernetRequest{uuid, ip}
}

// Write marshals an EthernetRequest message
func (m *EthernetRequest) Send(sr sendReceiver) error {
	var buf bytes.Buffer
	ty := uint8(1)
	if m.ip != nil {
		ty = uint8(8)
	}
	if err := binary.Write(&buf, binary.LittleEndian, ty); err != nil {
		return err
	}
	u, err := m.uuid.MarshalText()
	if err != nil {
		return err
	}
	if err := binary.Write(&buf, binary.LittleEndian, u); err != nil {
		return err
	}
	ip := uint32(0)
	if m.ip != nil {
		ip = binary.BigEndian.Uint32(m.ip.To4())
	}
	// The protocol uses little endian, not network endian
	if err := binary.Write(&buf, binary.LittleEndian, ip); err != nil {
		return err
	}
	_, err = sr.Send(buf.Bytes())
	return err
}

const max_ethernetResponse = 1500

func readEthernetResponse(sr sendReceiver) error {
	bs := make([]byte, max_ethernetResponse)
	n, err := sr.Recv(bs)
	if err != nil {
		return err
	}
	br := bytes.NewReader(bs[0:n])
	var responseType uint8
	if err := binary.Read(br, binary.LittleEndian, &responseType); err != nil {
		return err
	}
	switch responseType {
	case 1:
		return nil
	default:
		var len uint8
		if err := binary.Read(br, binary.LittleEndian, &len); err != nil {
			return err
		}
		message := make([]byte, len)
		if err := binary.Read(br, binary.LittleEndian, &message); err != nil {
			return err
		}

		return errors.New(string(message))
	}
}

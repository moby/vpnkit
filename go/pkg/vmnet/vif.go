package vmnet

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/moby/vpnkit/go/pkg/vpnkit/log"
	"github.com/pkg/errors"
)

// Vif represents an Ethernet device as a file descriptor.
// Clients should call Fd() and use send/recv to send ethernet frames.
type Vif struct {
	MTU           uint16
	MaxPacketSize uint16
	ClientMAC     net.HardwareAddr
	IP            net.IP
	Ethernet      Datagram // Ethernet allows clients to Read() and Write() raw ethernet frames.
	fds           []int
}

func (v *Vif) Close() error {
	for _, fd := range v.fds {
		_ = syscall.Close(fd)
	}
	return nil
}

// ensure we have a SOCK_DGRAM fd, by starting a proxy if necessary.
func (v *Vif) start(ethernet sendReceiver) error {
	if e, ok := ethernet.(Datagram); ok {
		// no proxy is required because we already have a datagram socket
		v.Ethernet = e
		return nil
	}
	// create a socketpair and feed one end into the sendReceiver
	fds, err := socketpair()
	if err != nil {
		return err
	}
	// remember the fds for Close()
	v.fds = fds[:]
	// client data will be written in this end
	v.Ethernet = Datagram{
		Fd: fds[0],
	}
	// and then proxied to the underlying sendReceiver
	proxy := Datagram{
		Fd: fds[1],
	}
	// proxy until the fds are closed
	go v.proxy(proxy, ethernet)
	go v.proxy(ethernet, proxy)
	return nil
}

func (v *Vif) proxy(from, to sendReceiver) {
	buf := make([]byte, v.MaxPacketSize)
	for {
		n, err := from.Recv(buf)
		if err != nil {
			log.Errorf("from.Read: %v", err)
			return
		}
		packet := buf[0:n]
		for {
			_, err := to.Send(packet)
			if err == nil {
				break
			}
			log.Errorf("to.write retrying packet of length %d: %v", len(packet), err)
			time.Sleep(10 * time.Millisecond)
		}
	}
}

type connectConfig struct {
	control  sendReceiver // vpnkit protocol message read/writer
	ethernet sendReceiver // ethenet frame read/write
	uuid     uuid.UUID    // vpnkit interface UUID
	IP       net.IP       // optional requested IP address
	pcap     string       // optional .pcap file
}

func connectVif(config connectConfig) (*Vif, error) {
	e := NewEthernetRequest(config.uuid, config.IP)
	if err := e.Send(config.control); err != nil {
		return nil, err
	}
	vif, err := readVif(config.control)
	if err != nil {
		return nil, err
	}
	if err := vif.start(config.ethernet); err != nil {
		return nil, err
	}
	config.pcap = "out.pcap"
	if config.pcap != "" {
		w, err := os.Create(config.pcap)
		if err != nil {
			return nil, errors.Wrapf(err, "creating %s", config.pcap)
		}
		p, err := NewPcapWriter(w)
		if err != nil {
			return nil, errors.Wrapf(err, "creating pcap in %s", config.pcap)
		}
		vif.Ethernet.pcap = p
	}
	vif.IP = config.IP
	if vif.IP == nil {
		IP, err := dhcpRequest(vif.Ethernet, vif.ClientMAC)
		if err != nil {
			return nil, err
		}
		vif.IP = IP
	}
	return vif, err
}

func readVif(fixedSize sendReceiver) (*Vif, error) {
	// https://github.com/moby/vpnkit/blob/6039eac025e0740e530f2ff11f57d6d990d1c4a1/src/hostnet/vmnet.ml#L160
	buf := make([]byte, 1+1+256)
	n, err := fixedSize.Recv(buf)
	if err != nil {
		return nil, errors.Wrap(err, "reading VIF metadata")
	}
	br := bytes.NewReader(buf[0:n])

	var responseType uint8
	if err := binary.Read(br, binary.LittleEndian, &responseType); err != nil {
		return nil, errors.Wrap(err, "reading response type")
	}
	if responseType != 1 {
		var len uint8
		if err := binary.Read(br, binary.LittleEndian, &len); err != nil {
			return nil, errors.Wrap(err, "reading error length")
		}
		message := make([]byte, len)
		if err := binary.Read(br, binary.LittleEndian, &message); err != nil {
			return nil, errors.Wrap(err, "reading error message")
		}
		return nil, errors.New(string(message))
	}

	var MTU, MaxPacketSize uint16
	if err := binary.Read(br, binary.LittleEndian, &MTU); err != nil {
		return nil, err
	}
	if err := binary.Read(br, binary.LittleEndian, &MaxPacketSize); err != nil {
		return nil, err
	}
	var mac [6]byte
	if err := binary.Read(br, binary.LittleEndian, &mac); err != nil {
		return nil, err
	}
	return &Vif{
		MTU:           MTU,
		MaxPacketSize: MaxPacketSize,
		ClientMAC:     mac[:],
	}, nil
}

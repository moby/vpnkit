package libproxy

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	// TCP protocol const
	TCP = 1
	// UDP protocol const
	UDP = 2
)

type destination struct {
	Proto uint8
	IP    net.IP
	Port  uint16
}

// Read header which describes TCP/UDP and destination IP:port
func unmarshalDestination(conn net.Conn) (destination, error) {
	d := destination{}
	if err := binary.Read(conn, binary.LittleEndian, &d.Proto); err != nil {
		return d, err
	}
	var length uint16
	// IP length
	if err := binary.Read(conn, binary.LittleEndian, &length); err != nil {
		return d, err
	}
	d.IP = make([]byte, length)
	if err := binary.Read(conn, binary.LittleEndian, &d.IP); err != nil {
		return d, err
	}
	if err := binary.Read(conn, binary.LittleEndian, &d.Port); err != nil {
		return d, err
	}
	return d, nil
}

func HandleMultiplexedConnections(conn net.Conn, quit chan struct{}) error {
	d, err := unmarshalDestination(conn)
	if err != nil {
		return fmt.Errorf("Failed to unmarshal header: %#v", err)
	}
	switch d.Proto {
	case TCP:
		backendAddr := net.TCPAddr{IP: d.IP, Port: int(d.Port), Zone: ""}
		if err := HandleTCPConnection(conn.(Conn), &backendAddr, quit); err != nil {
			return err
		}
	case UDP:
		backendAddr := &net.UDPAddr{IP: d.IP, Port: int(d.Port), Zone: ""}

		proxy, err := NewUDPProxy(backendAddr, NewUDPConn(conn), backendAddr)
		if err != nil {
			return fmt.Errorf("Failed to setup UDP proxy for %s: %#v", backendAddr, err)
		}
		proxy.Run()
		return nil
	default:
		return fmt.Errorf("Unknown protocol: %d", d.Proto)
	}
	return nil
}

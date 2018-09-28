package libproxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// Proto is the protocol of the flow
type Proto uint8

const (
	// TCP flow
	TCP Proto = 1
	// UDP flow
	UDP Proto = 2
)

type destination struct {
	Proto Proto
	IP    net.IP
	Port  uint16
}

// Read header which describes TCP/UDP and destination IP:port
func unmarshalDestination(r io.Reader) (destination, error) {
	d := destination{}
	if err := binary.Read(r, binary.LittleEndian, &d.Proto); err != nil {
		return d, err
	}
	var length uint16
	// IP length
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return d, err
	}
	d.IP = make([]byte, length)
	if err := binary.Read(r, binary.LittleEndian, &d.IP); err != nil {
		return d, err
	}
	if err := binary.Read(r, binary.LittleEndian, &d.Port); err != nil {
		return d, err
	}
	return d, nil
}

// Connection indicates whether the connection will use multiplexing or not.
type Connection int8

const (
	// Dedicated means this connection will not use multiplexing
	Dedicated Connection = iota + 1
	// Multiplexed means this connection will contain labelled sub-connections mixed together
	Multiplexed
)

type open struct {
	Connection Connection // Connection describes whether the opened connection should be dedicated or multiplexed
}

func unmarshalOpen(r io.Reader) (open, error) {
	o := open{}
	err := binary.Read(r, binary.LittleEndian, &o.Connection)
	return o, err
}

type data struct {
	payloadlen uint32
}

func unmarshalData(r io.Reader) (data, error) {
	d := data{}
	err := binary.Read(r, binary.LittleEndian, &d.payloadlen)
	return d, err
}

// Command is the action requested by a message.
type Command int8

const (
	// Open requests to open a connection to a backend service.
	Open Command = iota + 1
	// Close requests and then acknowledges the close of a sub-connection
	Close
	// Shutdown indicates that no more data will be written in this direction
	Shutdown
	// Data is a payload of a connection/sub-connection
	Data
)

type frame struct {
	Command Command // Command is the action erquested
	ID      uint32  // Id of the sub-connection, managed by the client
}

func unmarshalFrame(r io.Reader) (frame, error) {
	f := frame{}
	if err := binary.Read(r, binary.LittleEndian, &f.Command); err != nil {
		return f, err
	}
	if err := binary.Read(r, binary.LittleEndian, &f.ID); err != nil {
		return f, err
	}
	return f, nil
}

// HandleMultiplexedConnections unmarshals and handles requests from the server.
func HandleMultiplexedConnections(conn net.Conn, quit chan struct{}) error {
	f, err := unmarshalFrame(conn)
	if err != nil {
		return fmt.Errorf("Failed to unmarshal command frame: %v", err)
	}
	switch f.Command {
	case Open:
		o, err := unmarshalOpen(conn)
		if err != nil {
			return fmt.Errorf("Failed to unmarshal open command: %v", err)
		}
		switch o.Connection {
		case Multiplexed:
			return fmt.Errorf("Multiplexed connections are not implemented yet")
		case Dedicated:
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
		}
	default:
		return fmt.Errorf("Unknown command type: %v", f)
	}

	return nil
}

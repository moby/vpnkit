package vpnkit

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	p9p "github.com/docker/go-p9p"
	datakit "github.com/moby/datakit/api/go-datakit"
)

// Port describes a UDP or TCP port forward
type Port struct {
	client  *datakit.Client
	proto   string
	outIP   net.IP
	outPort uint16
	outPath string
	inIP    net.IP
	inPort  uint16
	inPath  string
	handle  *datakit.File
}

// NewPort constructs an instance of a TCP or UDP Port
func NewPort(connection *Connection, proto string, outIP net.IP, outPort uint16, inIP net.IP, inPort uint16) *Port {
	return &Port{connection.client, proto, outIP, outPort, "", inIP, inPort, "", nil}
}

// NewPath constructs an instance of a forwarded Unix path
func NewPath(connection *Connection, outPath, inPath string) *Port {
	return &Port{connection.client, "unix", nil, uint16(0), outPath, nil, uint16(0), inPath, nil}
}

// ListExposed returns a list of currently exposed ports
func ListExposed(connection *Connection) ([]*Port, error) {
	ctx := context.TODO()
	dirs, err := connection.client.List(ctx, []string{})
	if err != nil {
		return nil, err
	}
	results := make([]*Port, 0)

	for _, name := range dirs {
		port, err := parse(name)
		if err != nil {
			// there are some special files like "." and "README" to ignore
			continue
		}
		port.client = connection.client
		results = append(results, port)
	}

	return results, nil
}

// String returns a human-readable string
func (p *Port) String() string {
	return fmt.Sprintf("%s forward from %s:%d to %s:%d", p.proto, p.outIP.String(), p.outPort, p.inIP.String(), p.inPort)
}

// spec returns a string of the form proto:outIP:outPort:proto:inIP:inPort as
// understood by vpnkit
func (p *Port) spec() string {
	switch p.proto {
	case "tcp", "udp":
		return fmt.Sprintf("%s:%s:%d:%s:%s:%d", p.proto, p.outIP.String(), p.outPort, p.proto, p.inIP.String(), p.inPort)
	case "unix":
		return fmt.Sprintf("unix:%s:unix:%s", base64.StdEncoding.EncodeToString([]byte(p.outPath)), base64.StdEncoding.EncodeToString([]byte(p.inPath)))
	default:
		return "unknown protocol"
	}
}

func parse(name string) (*Port, error) {
	bits := strings.Split(name, ":")
	switch len(bits) {
	case 6:
		outProto := bits[0]
		outIP := net.ParseIP(bits[1])
		outPort, err := strconv.ParseUint(bits[2], 10, 16)
		if err != nil {
			return nil, err
		}
		inProto := bits[3]
		inIP := net.ParseIP(bits[4])
		inPort, err := strconv.ParseUint(bits[5], 10, 16)
		if err != nil {
			return nil, err
		}
		if outProto != inProto {
			return nil, errors.New("Failed to parse port: external proto is " + outProto + " but internal proto is " + inProto)
		}
		return &Port{nil, outProto, outIP, uint16(outPort), "", inIP, uint16(inPort), "", nil}, nil
	case 4:
		outProto := bits[0]
		outPathEnc := bits[1]
		outPath, err := base64.StdEncoding.DecodeString(outPathEnc)
		if err != nil {
			return nil, errors.New("Failed to base64 decode " + string(outPath))
		}
		inProto := bits[2]
		inPathEnc := bits[3]
		inPath, err := base64.StdEncoding.DecodeString(inPathEnc)
		if err != nil {
			return nil, errors.New("Failed to base64 decode " + string(inPath))
		}
		if outProto != "unix" || inProto != "unix" {
			return nil, errors.New("Failed to parse path: external proto is " + outProto + " and internal proto is " + inProto)
		}
		return &Port{nil, outProto, nil, uint16(0), string(outPath), nil, uint16(0), string(inPath), nil}, nil
	default:
		return nil, errors.New("Failed to parse port spec: " + name)
	}
}

// Expose asks vpnkit to expose the port
func (p *Port) Expose(ctx context.Context) error {
	if p.handle != nil {
		return errors.New("Port is already exposed")
	}
	spec := p.spec()
	client := p.client
	// use the spec also as a name
	name := spec

	log.Printf("Expose %s\n", spec)
	_ = client.Remove(ctx, name)

	err := client.Mkdir(ctx, name)
	if err != nil {
		log.Printf("Expose failed to create %s: %#v\n", name, err)
		return err
	}
	ctl, err := client.Open(ctx, p9p.OREAD, name, "ctl")
	if err != nil {
		log.Printf("Expose failed to open %s/ctl: %#v\n", name, err)
		return err
	}
	// NB we deliberately leak the fid because we use the clunk as a signal to
	// shutdown the forward.

	// Read any error from a previous session
	bytes := make([]byte, 100)
	n, err := ctl.Read(ctx, bytes, 0)
	if err != nil {
		log.Printf("Expose %s: failed to read response from ctl: %#v\n", spec, err)
		return err
	}
	_, _ = ctl.Read(ctx, bytes, int64(n))

	response := string(bytes)
	if !strings.HasPrefix(response, "ERROR no request received") {
		log.Printf("Expose %s: read error from previous operation: %s\n", spec, response[0:n])
	}

	request := []byte(spec)
	_, err = ctl.Write(ctx, request, 0)
	if err != nil {
		log.Printf("Expose %s: failed to write to ctl: %#v\n", spec, err)
		return err
	}

	n, err = ctl.Read(ctx, bytes, 0)
	if err != nil {
		log.Printf("Expose %s: failed to read response from ctl: %#v\n", spec, err)
		return err
	}

	_, _ = ctl.Read(ctx, bytes, int64(n))
	response = string(bytes)
	if strings.HasPrefix(response, "OK ") {
		response = strings.Trim(response[3:n], " \t\r\n")
		log.Printf("Expose %s: succeeded with %s\n", spec, response)
		p.handle = ctl
		return nil
	}

	log.Printf("Expose %s: failed: %s\n", spec, response[0:n])
	if strings.HasPrefix(response, "ERROR ") {
		response = strings.Trim(response[6:n], " \t\r\n")
		ctl.Close(ctx)
	}

	return errors.New(response)
}

// Unexpose asks vpnkit to hide the port again
func (p *Port) Unexpose(ctx context.Context) error {
	if p.handle == nil {
		ctl, err := p.client.Open(ctx, p9p.OREAD, p.spec(), "ctl")
		if err != nil {
			return errors.New("Port is not exposed")
		}
		p.handle = ctl
	}
	ctl := p.handle
	p.handle = nil
	// Any clunk frees the port
	ctl.Close(ctx)
	return nil
}

// Proto returns the protocol: either "tcp" or "udp"
func (p *Port) Proto() string {
	return p.proto
}

// OutIP returns the public IP
func (p *Port) OutIP() net.IP {
	return p.outIP
}

// OutPort returns the public port number
func (p *Port) OutPort() uint16 {
	return p.outPort
}

// InIP returns the private IP
func (p *Port) InIP() net.IP {
	return p.inIP
}

// InPort returns the private port number
func (p *Port) InPort() uint16 {
	return p.inPort
}

var enoent = p9p.MessageRerror{Ename: "file not found"}

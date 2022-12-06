package tunnel

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"

	"github.com/pkg/errors"
)

type Protocol string

const (
	TCP = Protocol("tcp")
	UDP = Protocol("udp")
)

// Request to open a tunnel.
type Request struct {
	Protocol Protocol
	DstIP    net.IP // DstIP is the Destination IP address.
	DstPort  int    // DstPort is the Destination Port.
	SrcIP    net.IP // SrcIP is the Source IP address.
	SrcPort  int    // SrcPort is the Source Port.
}

// ReadRequest from vpnkit to open a tunnel to a remote service.
func ReadRequest(r io.Reader) (*Request, error) {
	var len uint16
	if err := binary.Read(r, binary.LittleEndian, &len); err != nil {
		return nil, errors.Wrap(err, "reading request length")
	}
	buf := make([]byte, len)
	if err := binary.Read(r, binary.LittleEndian, &buf); err != nil {
		return nil, errors.Wrap(err, "reading request")
	}
	var req request
	if err := json.Unmarshal(buf, &req); err != nil {
		return nil, errors.Wrap(err, "parsing request json")
	}
	var result Request
	var err error
	result.Protocol, err = readProtocol(req.Protocol)
	if err != nil {
		return nil, err
	}
	result.Protocol = Protocol(req.Protocol)
	result.DstIP = net.ParseIP(req.DstIP)
	if result.DstIP == nil {
		return nil, errors.New("invalid DstIP " + req.DstIP)
	}
	result.DstPort = req.DstPort
	result.SrcIP = net.ParseIP(req.SrcIP)
	if result.SrcIP == nil {
		return nil, errors.New("invalid SrcIP " + req.SrcIP)
	}
	result.SrcPort = req.SrcPort
	return &result, nil
}

func readProtocol(p string) (Protocol, error) {
	switch p {
	case "tcp":
		return TCP, nil
	case "udp":
		return UDP, nil
	}
	return "", errors.New("unknown protocol: " + p)
}

// WriteRequest to vpnkit to open a tunnel to a remote service.
func (r *Request) Write(w io.Writer) error {
	req := request{
		Protocol: writeProtocol(r.Protocol),
		DstIP:    r.DstIP.String(),
		DstPort:  r.DstPort,
		SrcIP:    r.SrcIP.String(),
		SrcPort:  r.SrcPort,
	}
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, uint16(len(b))); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, b); err != nil {
		return err
	}
	return nil
}

func writeProtocol(p Protocol) string {
	switch p {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	}
	return "unknown"
}

// Matches protocol definition in src/hostnet/forwards.ml
type request struct {
	Protocol string `json:"protocol"`
	DstIP    string `json:"dst_ip"`
	DstPort  int    `json:"dst_port"`
	SrcIP    string `json:"src_ip"`
	SrcPort  int    `json:"src_port"`
}

// Response to the tunnel open request.
type Response struct {
	Accepted bool `json:"accepted"` // Accepted is true if the tunnel is now connected.
}

func ReadResponse(r io.Reader) (*Response, error) {
	var len uint16
	if err := binary.Read(r, binary.LittleEndian, &len); err != nil {
		return nil, errors.Wrap(err, "reading response length")
	}
	buf := make([]byte, len)
	if err := binary.Read(r, binary.LittleEndian, &buf); err != nil {
		return nil, errors.Wrap(err, "reading response")
	}
	var res Response
	if err := json.Unmarshal(buf, &res); err != nil {
		return nil, errors.Wrap(err, "parsing response json")
	}
	return &res, nil
}

func (r *Response) Write(w io.Writer) error {
	buf, err := json.Marshal(r)
	if err != nil {
		return errors.Wrap(err, "marsalling response")
	}
	len := uint16(len(buf))
	if err := binary.Write(w, binary.LittleEndian, len); err != nil {
		return errors.Wrap(err, "writing length")
	}
	_, err = w.Write(buf)
	return errors.Wrap(err, "writing payload")
}

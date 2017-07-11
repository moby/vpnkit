package vpnkit

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	p9p "github.com/docker/go-p9p"
	datakit "github.com/moby/datakit/api/go-datakit"
)

// Port represents a UDP or TCP exposed port
type Port struct {
	client  *datakit.Client
	proto   string
	outIP   net.IP
	outPort int16
	inIP    net.IP
	inPort  int16
	handle  *datakit.File
}

func NewPort(connection *Connection, proto string, outIP net.IP, outPort int16, inIP net.IP, inPort int16) *Port {
	return &Port{connection.client, proto, outIP, outPort, inIP, inPort, nil}
}

// spec returns a string of the form proto:outIP:outPort:proto:inIP:inPort as
// understood by vpnkit
func (p *Port) spec() string {
	return fmt.Sprintf("%s:%s:%d:%s:%s:%d", p.proto, p.outIP.String(), p.outPort, p.proto, p.inIP.String(), p.inPort)
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
		return errors.New("Port is not exposed")
	}
	ctl := p.handle
	p.handle = nil
	ctl.Close(ctx)
	return nil
}

var enoent = p9p.MessageRerror{Ename: "file not found"}

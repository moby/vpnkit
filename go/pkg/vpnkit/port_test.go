package vpnkit

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseRoundTrip(t *testing.T) {
	for _, port := range []Port{
		{
			Proto:   TCP,
			InIP:    net.ParseIP("192.168.0.1"),
			InPort:  8080,
			OutIP:   net.ParseIP("192.168.0.2"),
			OutPort: 8081,
		},
		{
			Proto:   TCP,
			InIP:    net.ParseIP("192.168.0.1"),
			InPort:  8080,
			OutIP:   net.ParseIP("192.168.0.2"),
			OutPort: 65000,
		},
		{
			Proto:   Unix,
			InPath:  "/tmp/foo",
			OutPath: "/tmp/bar",
		},
		{
			Proto:   Unix,
			InPath:  `\\.\pipe\foo`,
			OutPath: `\\.\pipe\bar`,
		},
	} {
		parsed, err := parse(port.spec())
		if err != nil {
			t.Fatalf("Cannot parse port spec: %s", err)
		}
		if parsed.spec() != port.spec() {
			t.Fatalf("Expected %s but has %s", parsed.spec(), port.spec())
		}
	}
}

func TestString(t *testing.T) {
	p := Port{
		Proto:   TCP,
		InIP:    net.ParseIP("192.168.0.1"),
		InPort:  8080,
		OutIP:   net.ParseIP("192.168.0.2"),
		OutPort: 8081,
	}
	assert.Equal(t, "tcp forward from 192.168.0.2:8081 to 192.168.0.1:8080", p.String())
}

func TestAnnotation(t *testing.T) {
	p := Port{
		Proto:      TCP,
		InIP:       net.ParseIP("192.168.0.1"),
		InPort:     8080,
		OutIP:      net.ParseIP("192.168.0.2"),
		OutPort:    8081,
		Annotation: "kubernetes",
	}
	assert.Equal(t, "kubernetes tcp forward from 192.168.0.2:8081 to 192.168.0.1:8080", p.String())
}

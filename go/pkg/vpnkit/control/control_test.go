package control

import (
	"context"
	"net"
	"testing"

	"github.com/moby/vpnkit/go/pkg/vpnkit"
	"github.com/stretchr/testify/assert"
)

func TestExposeIdempotent(t *testing.T) {
	c := Make()
	p := &vpnkit.Port{
		Proto:   vpnkit.TCP,
		OutIP:   net.ParseIP("127.0.0.1"),
		InIP:    net.ParseIP("127.0.0.1"),
		OutPort: 8080,
		InPort:  8080,
	}
	assert.Nil(t, c.Expose(context.Background(), p))
	assert.Nil(t, c.Expose(context.Background(), p))
}

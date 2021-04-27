package control

import (
	"context"
	"net"
	"testing"

	"github.com/moby/vpnkit/go/pkg/vpnkit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestExposeAnyThenListAndUnexpose(t *testing.T) {
	c := Make()
	p := &vpnkit.Port{
		Proto:   vpnkit.TCP,
		OutIP:   net.ParseIP("127.0.0.1"),
		InIP:    net.ParseIP("127.0.0.1"),
		OutPort: 0, // Any port will do
		InPort:  8080,
	}
	assert.Nil(t, c.Expose(context.Background(), p))
	all, err := c.ListExposed(context.Background())
	require.Nil(t, err)
	require.Len(t, all, 1)
	assert.Nil(t, c.Unexpose(context.Background(), &all[0]))
	all, err = c.ListExposed(context.Background())
	require.Nil(t, err)
	assert.Len(t, all, 0)
}

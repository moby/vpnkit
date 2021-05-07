package transport

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoSDDL(t *testing.T) {
	u := NewUnixTransport()
	// default security descriptor
	pipe := `\\.\pipe\mobyVpnkitTest`
	l, err := u.Listen(pipe)
	require.Nil(t, err)
	go func() {
		c, err := l.Accept()
		require.Nil(t, err)
		assert.Nil(t, c.Close())
	}()
	c, err := u.Dial(context.Background(), pipe)
	require.Nil(t, err)
	assert.Nil(t, c.Close())
}

package transport

import (
	"testing"

	"github.com/linuxkit/virtsock/pkg/vsock"
	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	a, err := parseAddr("2")
	assert.Nil(t, err)
	assert.EqualValues(t, vsock.CIDAny, a.cid)
	assert.Equal(t, uint32(2), a.port)
}

func TestParseCIDPort(t *testing.T) {
	a, err := parseAddr("3/2")
	assert.Nil(t, err)
	assert.EqualValues(t, uint32(3), a.cid)
	assert.Equal(t, uint32(2), a.port)
}

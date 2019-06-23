//+build !windows

package forward

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func TestMarshalInit(t *testing.T) {
	h := getOutgoingMessage()
	var buf bytes.Buffer
	assert.Nil(t, writeInitMessage(&buf, h))
	hh, err := readInitMessage(&buf)
	assert.Nil(t, err)
	assert.Equal(t, h, hh)

}

func TestMarshalCommand(t *testing.T) {
	c := bindIpv4Command
	var buf bytes.Buffer
	assert.Nil(t, writeCommand(&buf, c))
	cc, err := readCommand(&buf)
	assert.Nil(t, err)
	assert.Equal(t, c, cc)
}

func TestMarshalBindIpv4(t *testing.T) {
	b := bindIpv4{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 1234,
		TCP:  false,
	}
	var buf bytes.Buffer
	assert.Nil(t, writeBindIpv4(&buf, b))
	bb, err := readBindIpv4(&buf)
	assert.Nil(t, err)
	assert.Equal(t, b, *bb)
}

func TestBindVmnetd(t *testing.T) {
	localhost := net.ParseIP("127.0.0.1")
	f, err := listenTCPVmnet(localhost, 8081)
	assert.Nil(t, err)
	defer f.Close()
}

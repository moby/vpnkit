package tunnel

import (
	"bytes"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadWriteRequest(t *testing.T) {
	req := Request{
		Protocol: TCP,
		SrcIP:    net.ParseIP("127.0.0.1"),
		DstIP:    net.ParseIP("10.0.0.1"),
		SrcPort:  80,
		DstPort:  8080,
	}
	var buf bytes.Buffer
	require.Nil(t, req.Write(&buf))
	req2, err := ReadRequest(bytes.NewReader(buf.Bytes()))
	require.Nil(t, err)
	assert.Equal(t, req.Protocol, req2.Protocol)
	assert.Equal(t, req.SrcIP.String(), req2.SrcIP.String())
	assert.Equal(t, req.DstIP.String(), req2.DstIP.String())
	assert.Equal(t, req.SrcPort, req2.SrcPort)
	assert.Equal(t, req.DstPort, req2.DstPort)
}

func TestReadWriteResponse(t *testing.T) {
	res := Response{
		Accepted: true,
	}
	var buf bytes.Buffer
	require.Nil(t, res.Write(&buf))
	res2, err := ReadResponse(bytes.NewReader(buf.Bytes()))
	require.Nil(t, err)
	assert.Equal(t, res.Accepted, res2.Accepted)
}

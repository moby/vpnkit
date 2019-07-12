package transport

import (
	"fmt"
	"testing"

	"github.com/linuxkit/virtsock/pkg/hvsock"
	"github.com/linuxkit/virtsock/pkg/vsock"
	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	a, err := parseAddr("2")
	assert.Nil(t, err)
	assert.EqualValues(t, hvsock.GUIDZero, a.vmID)
	assert.EqualValues(t, vsock.CIDAny, a.cid)
	assert.Equal(t, uint32(2), a.port)
	assert.Equal(t, fmt.Sprintf("%08x-facb-11e6-bd58-64006a7986d3", 2), a.svcID.String())
}

func TestParseSvcID(t *testing.T) {
	a, err := parseAddr(fmt.Sprintf("%08x-facb-11e6-bd58-64006a7986d3", 2))
	assert.Nil(t, err)
	assert.EqualValues(t, hvsock.GUIDZero, a.vmID)
	assert.EqualValues(t, vsock.CIDAny, a.cid)
	// we don't try to compute the corresponding AF_VSOCK
	assert.Equal(t, fmt.Sprintf("%08x-facb-11e6-bd58-64006a7986d3", 2), a.svcID.String())
}

func TestParseVmIDPort(t *testing.T) {
	vmID := "12341234-1234-1234-1234-123412341234"
	a, err := parseAddr(fmt.Sprintf("%s/%08x-facb-11e6-bd58-64006a7986d3", vmID, 2))
	assert.Nil(t, err)
	assert.EqualValues(t, vmID, a.vmID.String())
	assert.EqualValues(t, vsock.CIDAny, a.cid)
	assert.Equal(t, fmt.Sprintf("%08x-facb-11e6-bd58-64006a7986d3", 2), a.svcID.String())
}

func TestParseVmIDPort2(t *testing.T) {
	vmID := "12341234-1234-1234-1234-123412341234"
	a, err := parseAddr(fmt.Sprintf("%s/%d", vmID, 2))
	assert.Nil(t, err)
	assert.EqualValues(t, vmID, a.vmID.String())
	assert.EqualValues(t, vsock.CIDAny, a.cid)
	assert.Equal(t, uint32(2), a.port)
	assert.Equal(t, fmt.Sprintf("%08x-facb-11e6-bd58-64006a7986d3", 2), a.svcID.String())
}

func TestParseCIDPort(t *testing.T) {
	a, err := parseAddr("3/2")
	assert.Nil(t, err)
	assert.EqualValues(t, hvsock.GUIDZero, a.vmID)
	assert.EqualValues(t, uint32(3), a.cid)
	assert.Equal(t, uint32(2), a.port)
	assert.Equal(t, fmt.Sprintf("%08x-facb-11e6-bd58-64006a7986d3", 2), a.svcID.String())
}

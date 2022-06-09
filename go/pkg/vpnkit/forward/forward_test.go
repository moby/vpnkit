package forward

import (
	"io"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/moby/vpnkit/go/pkg/libproxy"
	"github.com/moby/vpnkit/go/pkg/vpnkit"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

type mockMux struct {
	dialed *libproxy.Destination
}

func (m *mockMux) Run() {
}

func (m *mockMux) IsRunning() bool {
	return true
}

func (m *mockMux) Dial(d libproxy.Destination) (libproxy.MultiplexedConn, error) {
	m.dialed = &d
	return nil, errors.New("unimplemented Dial")
}

func (m *mockMux) Accept() (libproxy.MultiplexedConn, *libproxy.Destination, error) {
	return nil, nil, errors.New("unimplemented Accept")
}

func (m *mockMux) Close() error {
	return nil
}

func (m *mockMux) DumpState(_ io.Writer) {
}

type mockControl struct {
	mux       libproxy.Multiplexer
	Forwarder Maker
}

func (m *mockControl) Mux() libproxy.Multiplexer {
	return m.mux
}

func (m *mockControl) SetMux(mux libproxy.Multiplexer) {
	m.mux = mux
}

func findFreeLocalPort() int {
	return 0
}

func findFreeLocalTCPPorts(t *testing.T) (uint16, uint16) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	assert.Nil(t, err)

	l1, err := net.ListenTCP("tcp", addr)
	assert.Nil(t, err)
	defer l1.Close()

	l2, err := net.ListenTCP("tcp", addr)
	assert.Nil(t, err)
	defer l2.Close()

	return uint16(l1.Addr().(*net.TCPAddr).Port), uint16(l2.Addr().(*net.TCPAddr).Port)
}

func findFreeLocalUDPPorts(t *testing.T) (uint16, uint16) {
	addr, err := net.ResolveUDPAddr("udp", "localhost:0")
	assert.Nil(t, err)

	l1, err := net.ListenUDP("udp", addr)
	assert.Nil(t, err)
	defer l1.Close()

	l2, err := net.ListenUDP("udp", addr)
	assert.Nil(t, err)
	defer l2.Close()

	return uint16(l1.LocalAddr().(*net.UDPAddr).Port), uint16(l2.LocalAddr().(*net.UDPAddr).Port)
}

var localhost = net.ParseIP("127.0.0.1")

func TestTCP(t *testing.T) {
	ctrl := &mockControl{}
	outPort, inPort := findFreeLocalTCPPorts(t)
	port := vpnkit.Port{
		OutIP:   localhost,
		OutPort: outPort,
		InIP:    localhost,
		InPort:  inPort,
		Proto:   vpnkit.TCP,
	}
	f, err := ctrl.Forwarder.Make(ctrl, port)
	assert.Nil(t, err)
	f.Stop()
}

func TestTCPLeak(t *testing.T) {
	for i := 0; i < 2000; i++ {
		TestTCP(t)
	}
}

func TestUDP(t *testing.T) {
	ctrl := &mockControl{}
	mux := &mockMux{}
	ctrl.SetMux(mux)
	outPort, inPort := findFreeLocalUDPPorts(t)
	port := vpnkit.Port{
		OutIP:   localhost,
		OutPort: outPort,
		InIP:    localhost,
		InPort:  inPort,
		Proto:   vpnkit.UDP,
	}
	f, err := ctrl.Forwarder.Make(ctrl, port)
	assert.Nil(t, err)
	go f.Run()
	f.Stop()
}

func TestUDPLeak(t *testing.T) {
	for i := 0; i < 2000; i++ {
		TestUDP(t)
	}
}

func TestUnixForward(t *testing.T) {
	ctrl := &mockControl{}
	mux := &mockMux{}
	ctrl.SetMux(mux)
	outPath := "/tmp/outpath.sock"
	inPath := "/tmp/inpath.sock"
	if err := os.Remove(outPath); err != nil {
		assert.Equal(t, true, os.IsNotExist(err))
	}
	port := vpnkit.Port{
		OutPath: outPath,
		InPath:  inPath,
		Proto:   vpnkit.Unix,
	}
	f, err := ctrl.Forwarder.Make(ctrl, port)
	assert.Nil(t, err)
	a, err := net.Dial("unix", outPath)
	assert.Nil(t, err)
	defer a.Close()
	go f.Run()
	defer f.Stop()
	_, err = io.Copy(ioutil.Discard, a)
	assert.Nil(t, err)
	assert.Equal(t, &libproxy.Destination{
		Proto: libproxy.Unix,
		Path:  inPath,
	}, mux.dialed)
}

func TestUnixForwardAlreadyExists(t *testing.T) {
	ctrl := &mockControl{}
	mux := &mockMux{}
	ctrl.SetMux(mux)
	outPath := "/tmp/outpath.sock"
	inPath := "/tmp/inpath.sock"
	file, err := os.Create(outPath)
	assert.Nil(t, err)
	assert.Nil(t, file.Close())
	defer os.Remove(outPath)
	port := vpnkit.Port{
		OutPath: outPath,
		InPath:  inPath,
		Proto:   vpnkit.Unix,
	}
	_, err = ctrl.Forwarder.Make(ctrl, port)
	assert.NotNil(t, err)
}

func TestUnixForwardAlreadyExists2(t *testing.T) {
	ctrl := &mockControl{}
	mux := &mockMux{}
	ctrl.SetMux(mux)
	outPath := "/tmp/outpath.sock"
	inPath := "/tmp/inpath.sock"
	if err := os.Remove(outPath); err != nil {
		assert.Equal(t, true, os.IsNotExist(err))
	}
	l, err := net.Listen("unix", outPath)
	if l != nil {
		assert.Nil(t, l.Close())
	}
	port := vpnkit.Port{
		OutPath: outPath,
		InPath:  inPath,
		Proto:   vpnkit.Unix,
	}
	f, err := ctrl.Forwarder.Make(ctrl, port)
	assert.Nil(t, err)
	a, err := net.Dial("unix", outPath)
	assert.Nil(t, err)
	defer a.Close()
	go f.Run()
	defer f.Stop()
	_, err = io.Copy(ioutil.Discard, a)
	assert.Equal(t, &libproxy.Destination{
		Proto: libproxy.Unix,
		Path:  inPath,
	}, mux.dialed)
}

func TestUnixForwardDirNotExist(t *testing.T) {
	ctrl := &mockControl{}
	mux := &mockMux{}
	ctrl.SetMux(mux)
	outPath := "/tmp/port-forward-test/outpath.sock"
	inPath := "/tmp/port-forward-test/inpath.sock"
	if err := os.RemoveAll("/tmp/port-forward-test"); err != nil {
		assert.Equal(t, true, os.IsNotExist(err))
	}
	port := vpnkit.Port{
		OutPath: outPath,
		InPath:  inPath,
		Proto:   vpnkit.Unix,
	}
	f, err := ctrl.Forwarder.Make(ctrl, port)
	assert.Nil(t, err)
	a, err := net.Dial("unix", outPath)
	assert.Nil(t, err)
	defer a.Close()
	go f.Run()
	_, err = io.Copy(ioutil.Discard, a)
	assert.Equal(t, &libproxy.Destination{
		Proto: libproxy.Unix,
		Path:  inPath,
	}, mux.dialed)
}

// do the same with Unix and UDP

func TestAddressInUse(t *testing.T) {
	ctrl := &mockControl{}
	outPort, inPort := findFreeLocalTCPPorts(t)
	port := vpnkit.Port{
		OutIP:   localhost,
		OutPort: outPort,
		InIP:    localhost,
		InPort:  inPort,
		Proto:   vpnkit.TCP,
	}
	f1, err := ctrl.Forwarder.Make(ctrl, port)
	assert.Nil(t, err)
	f2, err := ctrl.Forwarder.Make(ctrl, port)
	if !strings.HasSuffix(err.Error(), "bind: address already in use") {
		t.Errorf("expected an address-already-in-use type of error: %v", err)
	}
	assert.Nil(t, f2)
	f1.Stop()
}

func TestInterfaceDoesNotExist(t *testing.T) {
	ctrl := &mockControl{}
	outPort, inPort := findFreeLocalTCPPorts(t)
	port := vpnkit.Port{
		OutIP:   net.ParseIP("1.2.3.4"), // not an IP on this machine
		OutPort: outPort,
		InIP:    localhost,
		InPort:  inPort,
		Proto:   vpnkit.TCP,
	}
	f, err := ctrl.Forwarder.Make(ctrl, port)
	if !strings.HasSuffix(err.Error(), "assign requested address") {
		t.Errorf("expected an no-such-address type of error: %v", err)
	}
	assert.Nil(t, f)
}

func TestRandomPortsTCP(t *testing.T) {
	maker := Maker{}
	f, err := maker.Make(nil, vpnkit.Port{InIP: net.IPv4(127, 0, 0, 1), InPort: 2, OutIP: net.IPv4(127, 0, 0, 1), OutPort: 0, Proto: vpnkit.TCP})
	assert.NoError(t, err)
	defer f.Stop()
	assert.NotEqual(t, uint16(0), f.Port().OutPort)
}

func TestRandomPortsUDP(t *testing.T) {
	maker := Maker{}
	f, err := maker.Make(nil, vpnkit.Port{InIP: net.IPv4(127, 0, 0, 1), InPort: 2, OutIP: net.IPv4(127, 0, 0, 1), OutPort: 0, Proto: vpnkit.UDP})
	assert.NoError(t, err)
	defer f.Stop()
	assert.NotEqual(t, uint16(0), f.Port().OutPort)
}

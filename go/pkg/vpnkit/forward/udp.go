package forward

import (
	"fmt"
	"net"

	"github.com/moby/vpnkit/go/pkg/libproxy"
	"github.com/moby/vpnkit/go/pkg/vpnkit"
	"github.com/moby/vpnkit/go/pkg/vpnkit/log"
	"github.com/pkg/errors"
)

// Listen on UDP sockets and forward to a remote multiplexer.

func makeUDP(c common) (*udp, error) {

	frontendAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", c.port.OutIP.String(), c.port.OutPort))
	if err != nil {
		return nil, errors.Wrapf(err, "unable to resolve frontend address for port %s", c.port.String())
	}
	backendAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", c.port.InIP.String(), c.port.InPort))
	if err != nil {
		return nil, errors.Wrapf(err, "unable to resolve backend address for port %s", c.port.String())
	}
	port := c.Port()
	l, err := listenUDP(port)
	if err != nil {
		return nil, err
	}
	if port.OutPort == 0 {
		addr, ok := l.LocalAddr().(*net.UDPAddr)
		if ok {
			port.OutPort = uint16(addr.Port)
		}
		c.port = port
	}
	dialer := &udpDialer{
		ctrl: c.ctrl,
	}
	proxy, err := libproxy.NewUDPProxy(frontendAddr, l, backendAddr, dialer)
	if err != nil {
		_ = l.Close()
		return nil, errors.Wrapf(err, "unable to initialise libproxy.UDPProxy for port %s", c.port.String())
	}
	return &udp{
		c,
		frontendAddr,
		backendAddr,
		proxy,
		l,
		nil,
	}, nil
}

type udp struct {
	common
	frontendAddr *net.UDPAddr
	backendAddr  *net.UDPAddr
	proxy        *libproxy.UDPProxy
	outside      libproxy.UDPListener
	inside       libproxy.UDPListener
}

func (u *udp) Run() {
	u.proxy.Run()
}

type udpDialer struct {
	ctrl vpnkit.Control
}

func (u *udpDialer) Dial(a *net.UDPAddr) (net.Conn, error) {
	dest := libproxy.Destination{
		Proto: libproxy.UDP,
		IP:    a.IP,
		Port:  uint16(a.Port),
	}
	mux := u.ctrl.Mux()
	return mux.Dial(dest)
}

func (u *udp) Stop() {
	log.Printf("removing %s", u.port.String())
	close(u.quit)
	if u.inside != nil {
		// only if Run() has been called
		u.inside.Close()
	}
	u.outside.Close()
}

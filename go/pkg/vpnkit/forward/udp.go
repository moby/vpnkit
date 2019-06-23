package forward

import (
	"github.com/moby/vpnkit/go/pkg/libproxy"
	"log"
)

// Listen on UDP sockets and forward to a remote multiplexer.

func makeUDP(c common) (*udp, error) {
	l, err := listenUDP(c.Port())
	if err != nil {
		return nil, err
	}

	return &udp{
		c,
		l,
		nil,
	}, nil
}

type udp struct {
	common
	outside libproxy.UDPListener
	inside  libproxy.UDPListener
}

func (u *udp) Run() {
	mux := u.ctrl.Mux()
	dest, err := mux.Dial(*u.dest)
	if err != nil {
		log.Printf("unable to connect on %s: %s", u.port.String(), err)
		return
	}
	u.inside = libproxy.NewUDPConn(dest)

	go u.proxyUDP(u.outside, u.inside)
	go u.proxyUDP(u.inside, u.outside)
	<-u.quit
}

func (u *udp) proxyUDP(left, right libproxy.UDPListener) {
	b := make([]byte, 65536) // max IP datagram size
	for {
		n, addr, err := left.ReadFromUDP(b)
		if err != nil {
			log.Printf("reading UDP on %s: %v", u.port.String(), err)
			return
		}
		pkt := b[0:n]
		_, err = right.WriteToUDP(pkt, addr)
		if err != nil {
			log.Printf("writing UDP on %s: %v", u.port.String(), err)
			return
		}
	}
}

func (u *udp) Stop() {
	log.Printf("Removing %s", u.port.String())
	if u.inside != nil {
		// only if Run() has been called
		u.inside.Close()
	}
	u.outside.Close()
	close(u.quit)
}

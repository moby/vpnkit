package control

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/moby/vpnkit/go/pkg/libproxy"
	"github.com/moby/vpnkit/go/pkg/vpnkit"
	"github.com/moby/vpnkit/go/pkg/vpnkit/forward"
	"github.com/moby/vpnkit/go/pkg/vpnkit/log"
	"github.com/moby/vpnkit/go/pkg/vpnkit/transport"
	"github.com/pkg/errors"
)

type Control struct {
	Forwarder forward.Maker // Forwarder makes local port forwards
	mux       libproxy.Multiplexer
	muxM      *sync.Mutex
	muxC      *sync.Cond
	forwards  map[string]forward.Forward
	forwardsM *sync.Mutex
}

func Make() *Control {
	var muxM sync.Mutex
	muxC := sync.NewCond(&muxM)
	var outsidesM sync.Mutex
	outsides := make(map[string]forward.Forward)
	return &Control{
		muxM:      &muxM,
		muxC:      muxC,
		forwards:  outsides,
		forwardsM: &outsidesM,
	}
}

func (c *Control) SetMux(m libproxy.Multiplexer) {
	c.muxM.Lock()
	defer c.muxM.Unlock()
	log.Println("established connection to vpnkit-forwarder")
	c.mux = m
	c.muxC.Broadcast()
}

func (c *Control) Mux() libproxy.Multiplexer {
	c.muxM.Lock()
	defer c.muxM.Unlock()
	for {
		if c.mux != nil {
			return c.mux
		}
		c.muxC.Wait()
	}
}

func portKey(port *vpnkit.Port) string {
	return port.String()
}

func (c *Control) Expose(_ context.Context, port *vpnkit.Port) error {
	if port == nil {
		return errors.New("cannot expose a nil Port")
	}
	key := portKey(port)
	c.forwardsM.Lock()
	defer c.forwardsM.Unlock()
	if _, ok := c.forwards[key]; ok {
		return errors.New("port already exposed: " + port.String())
	}
	forward, err := c.Forwarder.Make(c, *port)
	if err != nil {
		// This error (e.g. EADDRINUSE) is special and we want to show it to the user
		return &vpnkit.ExposeError{
			Message: err.Error(),
		}
	}
	c.forwards[key] = forward
	go forward.Run()
	return nil
}

func (c *Control) Unexpose(_ context.Context, port *vpnkit.Port) error {
	if port == nil {
		return errors.New("cannot unexpose a nil Port")
	}
	key := portKey(port)
	c.forwardsM.Lock()
	defer c.forwardsM.Unlock()
	forward, ok := c.forwards[key]
	if !ok {
		// make it idempotent
		return nil
	}
	forward.Stop()
	delete(c.forwards, key)
	return nil
}

func (c *Control) ListExposed(_ context.Context) ([]vpnkit.Port, error) {
	var results []vpnkit.Port
	for _, forward := range c.forwards {
		results = append(results, forward.Port())
	}
	return results, nil
}

func (c *Control) DumpState(_ context.Context, w io.Writer) error {
	m := c.Mux()
	m.DumpState(w)
	return nil
}

var _ vpnkit.Implementation = &Control{}
var _ vpnkit.Control = &Control{}

// Listen for incoming data connections
func (c *Control) Listen(path string, quit <-chan struct{}) {
	t := transport.Choose(path)
	l, err := t.Listen(path)
	if err != nil {
		log.Fatalf("unable to create a data server on %s %s: %s", t.String(), path, err)
	}
	for {
		// listen for one connection at a time
		log.Printf("listening on %s for data connection", path)
		conn, err := l.Accept()
		if err != nil {
			log.Printf("unable to accept connection on %s %s: %s", t.String(), path, err)
			continue
		}
		log.Printf("accepted data connection on %s %s", t.String(), path)
		c.handleDataConn(conn, quit)
	}
}

// Connect a data connection
func (c *Control) Connect(path string, quit <-chan struct{}) error {
	for {
		t := transport.Choose(path)
		log.Printf("dialing %s %s for data connection", t.String(), path)
		conn, err := t.Dial(context.Background(), path)
		if err != nil {
			// This can happen if the server is restarting
			log.Printf("unable to connect data on %s %s: %s. Is the server restarting? Will retry in 1s.", t.String(), path, err)
			time.Sleep(time.Second)
			continue
		}
		log.Printf("connected data connection on %s %s", t.String(), path)
		c.handleDataConn(conn, quit)
	}
}

// handle data-plane forwarding
func (c *Control) handleDataConn(rw io.ReadWriteCloser, quit <-chan struct{}) {
	defer rw.Close()

	mux := libproxy.NewMultiplexer("local", rw)
	mux.Run()
	c.SetMux(mux)
	for {
		conn, destination, err := mux.Accept()
		if err != nil {
			log.Errorf("error accepting subconnection: %v", err)
			return
		}
		go libproxy.Forward(conn, *destination, quit)
	}
}

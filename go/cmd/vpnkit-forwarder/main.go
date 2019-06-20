package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/moby/vpnkit/go/pkg/vpnkit"
	"github.com/moby/vpnkit/go/pkg/vpnkit/control"
	"github.com/moby/vpnkit/go/pkg/vpnkit/transport"
)

var (
	controlVsock string
	controlPipe  string
	dataListen   string
	dataConnect  string
	debug        bool
)

// Listen on either AF_VSOCK or AF_HVSOCK (depending on the kernel) for multiplexed connections
func main() {
	flag.StringVar(&controlVsock, "control-vsock", "", "AF_VSOCK port to listen for control connections on")
	flag.StringVar(&controlPipe, "control-pipe", "", "Unix domain socket or Windows named pipe to listen for control connections on")
	flag.StringVar(&dataListen, "data-listen", "", "AF_VSOCK port to listen for data connections on")
	flag.StringVar(&dataConnect, "data-connect", fmt.Sprintf("%d", vpnkit.DefaultDataVsock), "AF_VSOCK port to connect to on the host for data connections")
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")
	flag.Parse()

	// vpnkit-forwarder --control-vsock --control-pipe --data-listen --data-connect
	quit := make(chan struct{})
	defer close(quit)

	ctrl := control.Make()
	if controlVsock == "" {
		controlVsock = fmt.Sprintf("%d", vpnkit.DefaultControlVsock)
	}
	t := transport.NewVsockTransport()
	s, err := vpnkit.NewServer(controlVsock, t, ctrl)
	if err != nil {
		log.Fatalf("unable to create a control server on AF_VSOCK port %s: %s", controlVsock, err)
	}
	s.Start()
	if controlPipe != "" {
		t := transport.NewUnixTransport()
		s, err := vpnkit.NewServer(controlPipe, t, ctrl)
		if err != nil {
			log.Fatalf("unable to create a control server on Pipe %s: %s", controlPipe, err)
		}
		s.Start()
	}
	if dataListen != "" {
		go ctrl.Listen(dataListen, quit)
	}
	if dataConnect != "" {
		go ctrl.Connect(dataConnect, quit)
	}
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	log.Println("Interrupt received, shutting down")
}

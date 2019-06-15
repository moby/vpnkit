package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"

	vpnkit "github.com/moby/vpnkit/go/pkg/vpnkit"
	"github.com/moby/vpnkit/go/pkg/vpnkit/transport"
)

// List currently exposed ports

var (
	controlVsock string
	controlPipe  string
)

func connectClient() (vpnkit.Client, error) {
	if controlVsock != "" {
		t := transport.NewVsockTransport()
		return vpnkit.NewClient(t, controlVsock)
	}
	if controlPipe != "" {
		t := transport.NewUnixTransport()
		return vpnkit.NewClient(t, controlPipe)
	}
	return nil, errors.New("Please supply either -control-vsock or -control-pipe arguments")
}

func main() {
	flag.StringVar(&controlVsock, "control-vsock", "", "AF_VSOCK port to listen for control connections on")
	flag.StringVar(&controlPipe, "control-pipe", "", "Unix domain socket or Windows named pipe to listen for control connections on")
	flag.Parse()

	c, err := connectClient()
	if err != nil {
		log.Fatal(err)
	}
	ports, err := c.ListExposed(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	for _, p := range ports {
		fmt.Println(p.String())
	}
}

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/moby/vpnkit/go/pkg/vpnkit"
)

// List currently exposed ports

var (
	control string

	debug bool
)

func main() {
	flag.StringVar(&control, "control", "", "AF_VSOCK port or socket/Pipe path to connect to")
	flag.BoolVar(&debug, "debug", false, "also include debugging information")
	flag.Parse()

	if control == "" {
		log.Fatal("Please supply a -control argument")
	}
	c, err := vpnkit.NewClient(control)
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
	if debug {
		if err := c.DumpState(context.Background(), os.Stderr); err != nil {
			log.Fatal(err)
		}
	}
}

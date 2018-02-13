package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	vpnkit "github.com/moby/vpnkit/go/pkg/vpnkit"
)

// List currently exposed ports

func main() {
	path := flag.String("vpnkit", "", "path to vpnkit's control socket")
	flag.Parse()

	c, err := vpnkit.NewConnection(context.Background(), *path)
	if err != nil {
		log.Fatal(err)
	}
	ports, err := vpnkit.ListExposed(c)
	if err != nil {
		log.Fatal(err)
	}
	for _, p := range ports {
		fmt.Println(p.String())
	}
}

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	vpnkit "github.com/moby/vpnkit/go/pkg/vpnkit"
)

// List currently exposed ports

func main() {
	path := flag.String("vpnkit", os.Getenv("HOME")+"/Library/Containers/com.docker.docker/Data/s51", "path to vpnkit's control socket")
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

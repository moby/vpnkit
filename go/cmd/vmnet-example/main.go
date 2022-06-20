package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/uuid"
	"github.com/moby/vpnkit/go/pkg/vmnet"
)

var path string

func main() {
	flag.StringVar(&path, "path", "", "path to vmnet socket")
	flag.Parse()
	if path == "" {
		fmt.Fprintf(os.Stderr, "Please supply a --path argument\n")
	}
	vm, err := vmnet.Connect(context.Background(), vmnet.Config{
		Path: path,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer vm.Close()
	log.Println("connected to vmnet service")
	u, err := uuid.NewRandom()
	if err != nil {
		log.Fatal(err)
	}
	vif, err := vm.ConnectVif(u)
	if err != nil {
		log.Fatal(err)
	}
	defer vif.Close()
	log.Printf("VIF has IP %s", vif.IP)
	log.Printf("SOCK_DGRAM fd: %d", vif.Ethernet.Fd)
}

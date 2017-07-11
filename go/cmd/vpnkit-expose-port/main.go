package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"

	vpnkit "github.com/moby/vpnkit/go/pkg/vpnkit"
)

// Expose ports via the control interface

func main() {
	proto := flag.String("proto", "tcp", "proxy protocol")
	hostIP := flag.String("host-ip", "", "host ip")
	hostPort := flag.Int("host-port", -1, "host port")
	containerIP := flag.String("container-ip", "", "container ip")
	containerPort := flag.Int("container-port", -1, "container port")
	path := flag.String("vpnkit", os.Getenv("HOME")+"/Library/Containers/com.docker.docker/Data/s51", "path to vpnkit's control socket")
	flag.Parse()

	c, err := vpnkit.NewConnection(context.Background(), *path)
	if err != nil {
		log.Fatal(err)
	}
	outIP := net.ParseIP(*hostIP)
	outPort := int16(*hostPort)
	inIP := net.ParseIP(*containerIP)
	inPort := int16(*containerPort)
	p := vpnkit.NewPort(c, *proto, outIP, outPort, inIP, inPort)
	if err = p.Expose(context.Background()); err != nil {
		log.Fatal(err)
	}
	defer p.Unexpose(context.Background())

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
}

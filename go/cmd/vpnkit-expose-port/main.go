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
	proto := flag.String("proto", "tcp", "proxy protocol (tcp/udp/unix)")
	hostIP := flag.String("host-ip", "", "host ip")
	hostPort := flag.Int("host-port", -1, "host port")
	hostPath := flag.String("host-path", "", "host path to forward")
	containerIP := flag.String("container-ip", "", "container ip")
	containerPort := flag.Int("container-port", -1, "container port")
	containerPath := flag.String("container-path", "", "container path to forward to")
	path := flag.String("vpnkit", "", "path to vpnkit's control socket")
	flag.Parse()

	c, err := vpnkit.NewConnection(context.Background(), *path)
	if err != nil {
		log.Fatal(err)
	}
	switch *proto {
	case "ucp", "udp":
		outIP := net.ParseIP(*hostIP)
		outPort := uint16(*hostPort)
		inIP := net.ParseIP(*containerIP)
		inPort := uint16(*containerPort)
		p := vpnkit.NewPort(c, *proto, outIP, outPort, inIP, inPort)
		if err = p.Expose(context.Background()); err != nil {
			log.Fatal(err)
		}
		defer p.Unexpose(context.Background())
	case "unix":
		p := vpnkit.NewPath(c, *hostPath, *containerPath)
		if err = p.Expose(context.Background()); err != nil {
			log.Fatal(err)
		}
		defer p.Unexpose(context.Background())
	default:
		log.Fatalf("Unknown protocol %s. Use tcp, udp or unix", *proto)
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
}

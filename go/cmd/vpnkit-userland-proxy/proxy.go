package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

var interactiveMode bool

// sendError signals the error to the parent and quits the process.
func sendError(err error) {
	if interactiveMode {
		log.Fatal("Failed to set up proxy", err)
	}
	f := os.NewFile(3, "signal-parent")

	fmt.Fprintf(f, "1\n%s", err)
	f.Close()
	os.Exit(1)
}

// sendOK signals the parent that the forward is running.
func sendOK() {
	if interactiveMode {
		log.Println("Proxy running")
		return
	}
	f := os.NewFile(3, "signal-parent")
	fmt.Fprint(f, "0\n")
	f.Close()
}

// Map dynamic TCP ports onto vsock ports over this offset
var vSockTCPPortOffset = 0x10000

// Map dynamic UDP ports onto vsock ports over this offset
var vSockUDPPortOffset = 0x20000

// From docker/libnetwork/portmapper/proxy.go:

type localBind int

const (
	bestEffortLocalBind = localBind(0)
	alwaysLocalBind     = localBind(1)
	neverLocalBind      = localBind(2)
)

// parseHostContainerAddrs parses the flags passed on reexec to create the TCP or UDP
// net.Addrs to map the host and container ports
func parseHostContainerAddrs() (host net.Addr, port int, container net.Addr, bind localBind) {
	var (
		proto         = flag.String("proto", "tcp", "proxy protocol")
		hostIP        = flag.String("host-ip", "", "host ip")
		hostPort      = flag.Int("host-port", -1, "host port")
		containerIP   = flag.String("container-ip", "", "container ip")
		containerPort = flag.Int("container-port", -1, "container port")
		interactive   = flag.Bool("i", false, "print success/failure to stdout/stderr")
		local         = flag.String("local-bind", "", "bind only on the Host, not in the VM (default: best-effort)")
	)
	localBind := bestEffortLocalBind // default
	// Attempt to remain backwards compatible for existing scripts which have `-no-local-ip` as a flag.
	// Note there are no existing scripts which attempt to provide a `true` or `false` argument.
	var args []string
	for _, arg := range os.Args {
		if arg == "-no-local-ip" {
			localBind = neverLocalBind
			continue
		}
		args = append(args, arg)
	}
	os.Args = args
	flag.Parse()

	// Support -no-local-ip for backwards compatibility
	switch *local {
	case "":
		// default from code above
	case "best-effort":
		localBind = bestEffortLocalBind
	case "always":
		localBind = alwaysLocalBind
	case "never":
		localBind = neverLocalBind
	default:
		log.Fatal("-local-bind argument must be 'best-effort' or 'always' or 'never'")
	}

	interactiveMode = *interactive

	switch *proto {
	case "tcp":
		host = &net.TCPAddr{IP: net.ParseIP(*hostIP), Port: *hostPort}
		port = vSockTCPPortOffset + *hostPort
		container = &net.TCPAddr{IP: net.ParseIP(*containerIP), Port: *containerPort}
	case "udp":
		host = &net.UDPAddr{IP: net.ParseIP(*hostIP), Port: *hostPort}
		port = vSockUDPPortOffset + *hostPort
		container = &net.UDPAddr{IP: net.ParseIP(*containerIP), Port: *containerPort}
	default:
		log.Fatalf("unsupported protocol %s", *proto)
	}
	return host, port, container, localBind
}

func handleStopSignals() {
	s := make(chan os.Signal, 10)
	signal.Notify(s, os.Interrupt, syscall.SIGTERM, syscall.SIGSTOP)

	for range s {
		os.Exit(0)
	}
}

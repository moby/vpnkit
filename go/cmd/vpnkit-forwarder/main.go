package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"syscall"

	"github.com/moby/vpnkit/go/pkg/vpnkit/control"
	"github.com/moby/vpnkit/go/pkg/vpnkit/http"
)

var (
	controlListen string
	dataListen    string
	dataConnect   string
	debug         bool
)

// Listen on either AF_VSOCK or AF_HVSOCK (depending on the kernel) for multiplexed connections
func main() {
	flag.StringVar(&controlListen, "control-listen", "", "AF_VSOCK port or socket/Pipe path to listen for control connections")
	flag.StringVar(&dataListen, "data-listen", "", "AF_VSOCK port or socket/Pipe path to listen for data connections on")
	flag.StringVar(&dataConnect, "data-connect", "", "AF_VSOCK port or socket/Pipe path to connect to on the host for data connections")
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")
	flag.Parse()
	if dataListen == "" && dataConnect == "" {
		log.Fatal("You must provide either -data-listen or -data-connect to establish a data connection")
	}
	quit := make(chan struct{})
	defer close(quit)

	ctrl := control.Make()

	if controlListen != "" {
		s, err := http.NewServer(controlListen, ctrl)
		if err != nil {
			log.Fatalf("unable to create a control server on %s: %s", controlListen, err)
		}
		s.Start()
	} else {
		log.Println("Not starting a control server")
	}

	if dataListen != "" {
		go ctrl.Listen(dataListen, quit)
	}
	if dataConnect != "" {
		go func() {
			if err := ctrl.Connect(dataConnect, quit); err != nil {
				fmt.Printf("unable to connect data on %s: %s\n", dataConnect, err)
			}
		}()
	}
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGHUP)
		for {
			<-c
			log.Println("Writing profiles to current directory")
			for _, profile := range pprof.Profiles() {
				filename := filepath.Join(os.TempDir(), profile.Name()+".profile")
				log.Printf("Writing %s", filename)
				f, err := os.Create(filename)
				if err != nil {
					log.Fatalf("unable to create %s: %v", filename, err)
				}
				if err := profile.WriteTo(f, 2); err != nil {
					log.Fatalf("writing profile: %s", err)
				}
				f.Close()
			}
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	log.Println("Interrupt received, shutting down")
}

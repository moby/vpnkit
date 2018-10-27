package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"

	"github.com/moby/vpnkit/go/pkg/vpnkit"
)

func main() {
	dialer := &vpnkit.Dialer{}

	switch runtime.GOOS {
	case "darwin":
		flag.StringVar(&dialer.HyperkitConnectPath, "hyperkit-connect", "", "path to hyperkit connect socket")
	case "windows":
		flag.StringVar(&dialer.HyperVVMID, "vm-guid", "", "Hyper-V VM GUID")
	}
	flag.IntVar(&dialer.Port, "port", 0, "AF_VSOCK port of vpnkit-forwarder")
	flag.Parse()

	transport := &http.Transport{
		Dial: dialer.Dial,
	}
	client := &http.Client{Transport: transport}
	url := "https://www.docker.com"
	resp, err := client.Get(url)
	if err != nil {
		log.Fatalf("Failed to HTTP GET %s: %v", url, err)
	}
	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		log.Fatalf("Failed to read the body: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		log.Fatalf("Failed to close the body: %v", err)
	}
}

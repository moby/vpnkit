package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"

	"github.com/google/uuid"
	vpnkit "github.com/moby/vpnkit/go/pkg/vpnkit"
)

// Register an ethernet UUID, discover the IP

func main() {
	path := flag.String("vpnkit", os.Getenv("HOME")+"/Library/Containers/com.docker.docker/Data/s50", "path to vpnkit's ethernet socket")
	u := flag.String("uuid", "", "UUID for the network interface")
	IP := flag.String("ip", "", "the IP we would like to use")
	flag.Parse()

	Uuid, err := uuid.Parse(*u)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	vmnet, err := vpnkit.NewVmnet(ctx, *path)
	if err != nil {
		log.Fatal(err)
	}
	defer vmnet.Close()

	var vif *vpnkit.Vif
	if *IP == "" {
		vif, err = vmnet.ConnectVif(Uuid)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		ip := net.ParseIP(*IP)
		if ip == nil {
			log.Fatal("Failed to parse IP address")
		}
		vif, err = vmnet.ConnectVifIP(Uuid, ip)
		if err != nil {
			log.Fatal(err)
		}
	}
	log.Printf("VIF has MAC %s", vif.ClientMAC.String())
	log.Printf("VIF has IP %s", vif.IP.String())
}

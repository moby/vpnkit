package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/google/uuid"
	vpnkit "github.com/moby/vpnkit/go/pkg/vpnkit"
)

// Register an ethernet UUID, discover the IP

func main() {
	path := flag.String("vpnkit", os.Getenv("HOME")+"/Library/Containers/com.docker.docker/Data/s50", "path to vpnkit's ethernet socket")
	u := flag.String("uuid", "", "UUID for the network interface")
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

	vif, err := vmnet.ConnectVif(Uuid)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("VIF has MAC %s", vif.ClientMAC.String())
	log.Printf("VIF has IP %s", vif.IP.String())
}

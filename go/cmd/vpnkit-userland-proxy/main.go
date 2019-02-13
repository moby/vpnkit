package main

import (
	"os"
	"path"
)

func main() {
	if path.Base(os.Args[0]) == "vpnkit-forwarder" {
		manyPorts()
		return
	}
	onePort()
}

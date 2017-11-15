package main

import (
	"os"

	"github.com/moby/vpnkit/go/pkg/libproxy"
)

func onePort() {
	host, _, container, localIP := parseHostContainerAddrs()

	var ipP libproxy.Proxy
	var err error

	if localIP {
		ipP, err = libproxy.NewBestEffortIPProxy(host, container)
		if err != nil {
			sendError(err)
		}
	}

	ctl, err := libproxy.ExposePort(host, container)
	if err != nil {
		sendError(err)
	}

	go handleStopSignals()
	// TODO: avoid this line if we are running in a TTY
	sendOK()
	if ipP != nil {
		ipP.Run()
	} else {
		select {} // sleep forever
	}
	ctl.Close() // ensure ctl remains alive and un-GCed until here
	os.Exit(0)
}

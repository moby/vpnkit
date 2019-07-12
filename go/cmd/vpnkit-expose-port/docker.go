package main

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/ssh/terminal"
)

// Communicate success/failure with the parent Docker process

func isOnTerminal() bool {
	return terminal.IsTerminal(int(os.Stdout.Fd()))
}

// sendError signals the error to the parent and quits the process.
func sendError(err error) {
	if debug {
		fmt.Printf("Sending to fd 3:\n1\n%s", err)
		os.Exit(1)
	}
	if isOnTerminal() || interactive {
		log.Fatal("Failed to set up proxy", err)
	}
	f := os.NewFile(3, "signal-parent")

	fmt.Fprintf(f, "1\n%s", err)
	f.Close()
	os.Exit(1)
}

// sendOK signals the parent that the forward is running.
func sendOK() {
	if debug {
		fmt.Printf("sending to fd 3:\n0\n")
		return
	}
	if isOnTerminal() || interactive {
		log.Println("Proxy running")
		return
	}
	f := os.NewFile(3, "signal-parent")
	fmt.Fprint(f, "0\n")
	f.Close()
}

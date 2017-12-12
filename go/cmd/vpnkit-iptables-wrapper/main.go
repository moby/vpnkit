package main

/*
Spawns vpnkit-expose-port instances for swarm ports by wrapping calls to iptables in the format:

--wait -t nat -I DOCKER-INGRESS -p tcp --dport 80 -j DNAT --to-destination 172.18.0.2:80
--wait -t nat -D DOCKER-INGRESS -p tcp --dport 80 -j DNAT --to-destination 172.18.0.2:80
*/

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

const iptablesPath = "/sbin/iptables"
const configKey = "/var/config/vpnkit/native-port-forwarding"
const vpnKitExposePort = "vpnkit-expose-port" // must be in PATH
const pidDir = "/var/run/service-port-opener"

type exposedPort struct {
	proto string
	dport string // host port
	ip    string // container ip
	port  string // container port
}

type stringVal struct {
	val string
}

type ipPortVal struct {
	IP   string
	Port string
}

// pidFilename returns the path to a pid file for the exposed port
func pidFileName(port exposedPort) string {
	return fmt.Sprintf("%s/%s.%s.%s.%s.pid", pidDir, port.proto, port.dport, port.ip, port.port)
}

// insert starts a vpnKitExposePort process and writes the pid to a file in pidDir
func insert(vpnKitExposePort string, port exposedPort) error {
	cmd := exec.Command(vpnKitExposePort, "-proto", port.proto, "-container-ip", port.ip, "-container-port", port.port, "-host-ip", "0.0.0.0", "-host-port", port.dport, "-i", "-no-local-ip")

	if err := cmd.Start(); err != nil {
		return err
	}

	pidFile := pidFileName(port)
	pidS := strconv.Itoa(cmd.Process.Pid)
	if err := ioutil.WriteFile(pidFile, []byte(pidS), 0644); err != nil {
		return err
	}

	return nil
}

// remove finds the corresponding pid file in pidDir and kills the vpnKitExposePort process
func remove(port exposedPort) error {
	pidFile := pidFileName(port)

	buf, err := ioutil.ReadFile(pidFile)
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(string(buf))
	if err != nil {
		return err
	}
	err = syscall.Kill(pid, syscall.SIGTERM)
	if err != nil {
		return err
	}

	return os.Remove(pidFile)
}

// useNativePortForwarding is true if the key file exists and contains "1" or "true"
func useNativePortForwarding() bool {
	if f, err := os.Open(configKey); err == nil {
		buf := bufio.NewScanner(f)
		if buf.Scan() {
			s := strings.ToLower(strings.Trim(buf.Text(), " \n"))
			return s == "1" || s == "true"
		}
		defer f.Close()
	} else {
		if !os.IsNotExist(err) { // If error is different from file not found, output error message (but continue)
			log.Println("Error opening", configKey, ":", err)
		}
	}
	return false
}

func (o *stringVal) Set(s string) error {
	o.val = s
	return nil
}

func (o *stringVal) String() string {
	return o.val
}

func (o *ipPortVal) Set(s string) error {
	r := strings.SplitN(s, ":", 2)
	if len(r) != 2 {
		return fmt.Errorf("invalid ip:port pair")
	}
	o.IP = r[0]
	o.Port = r[1]
	return nil
}

func (o *ipPortVal) String() string {
	return fmt.Sprintf("%s:%s", o.IP, o.Port)
}

// matchStringArray matches an array of strings against a pattern that can contain strings or *flag.Value structs.
// Strings are matched against the input, Value structs will be set to the corresponding value in the input array.
// May produce partial matches. Error is nil if the full pattern was matched.
func matchStringArray(input []string, pattern []interface{}) error {
	var err error
	if len(input) < len(pattern) {
		return fmt.Errorf("input shorter than pattern")
	}
	for idx := range pattern {
		switch pattern[idx].(type) {
		case string:
			if pattern[idx].(string) != input[idx] {
				return fmt.Errorf("input doesn't match pattern")
			}
		case flag.Value:
			if err = pattern[idx].(flag.Value).Set(input[idx]); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown type in pattern")
		}
	}
	return nil
}

func main() {
	var err error
	var vpnKitExposePortPath string
	var iptables string

	if iptables, err = exec.LookPath(iptablesPath); err != nil {
		log.Fatalln(err)
	}

	if !useNativePortForwarding() {
		if vpnKitExposePortPath, err = exec.LookPath(vpnKitExposePort); err != nil {
			log.Fatalln(err)
		}

		if err = os.MkdirAll(pidDir, 0755); err != nil {
			log.Fatalln(err)
		}

		/* This workaround is from the ocaml version. Original comment:
		Close the vast number of fds I've inherited from docker
		TODO(djs55): revisit, possibly by filing a docker/docker issue */

		var f *os.File
		for i := 3; i < 1024; i++ {
			f = os.NewFile(uintptr(i), "")
			f.Close()
		}

		// Expose port via vpnkit
		var optProto, optDport, optAction stringVal
		var optIPPort ipPortVal

		err = matchStringArray(os.Args[1:], []interface{}{"--wait", "-t", "nat", &optAction, "DOCKER-INGRESS", "-p", &optProto, "--dport", &optDport, "-j", "DNAT", "--to-destination", &optIPPort})

		if err == nil {
			port := exposedPort{optProto.String(), optDport.String(), optIPPort.IP, optIPPort.Port}
			switch optAction.String() {
			case "-D":
				remove(port)
			case "-I":
				insert(vpnKitExposePortPath, port)
			}
		} else {
			// ignore errors here, just pass to iptables
		}
	}

	// Run iptables
	cmd := exec.Command(iptables, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	if err = cmd.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			// exit with exit code from process
			status := exitError.Sys().(syscall.WaitStatus)
			os.Exit(status.ExitStatus())
		} else {
			// no exit code, report error and exit 1
			fmt.Println(err)
			os.Exit(1)
		}
	}

}

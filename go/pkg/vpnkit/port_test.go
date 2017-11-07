package vpnkit

import "testing"

func TestParseRoundTrip(t *testing.T) {
	specs := []string{
		"tcp:192.168.0.1:8080:tcp:192.168.0.2:8081",
		"tcp:192.168.0.1:8080:tcp:192.168.0.2:65000",
	}
	for _, spec := range specs {
		port, err := parse(spec)
		if err != nil {
			t.Fatalf("Cannot parse port spec: %s", err)
		}
		if spec != port.spec() {
			t.Fatalf("Expected %s but has %s", spec, port.spec())
		}
	}
}

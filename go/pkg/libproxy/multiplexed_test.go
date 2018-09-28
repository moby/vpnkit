package libproxy

import (
	"bytes"
	"io/ioutil"
	"testing"
)

// By default this is intended to be run from the Dockerfile
var binDir = "../../test_inputs/"

func TestParseOpenDedicated(t *testing.T) {
	b, err := ioutil.ReadFile(binDir + "open_dedicated_connection.bin")
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewBuffer(b)
	f, err := unmarshalFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, f.Command, Open)
	assertEqual(t, f.ID, uint32(4))
	o, err := unmarshalOpen(r)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, o.Connection, Dedicated)
	d, err := unmarshalDestination(r)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, d.Proto, TCP)
	assertEqual(t, d.IP.String(), "127.0.0.1")
	assertEqual(t, d.Port, uint16(8080))
}

func TestParseOpenMultiplexed(t *testing.T) {
	b, err := ioutil.ReadFile(binDir + "open_multiplexed_connection.bin")
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewBuffer(b)
	f, err := unmarshalFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, f.Command, Open)
	assertEqual(t, f.ID, uint32(5))
	o, err := unmarshalOpen(r)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, o.Connection, Multiplexed)
	d, err := unmarshalDestination(r)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, d.Proto, UDP)
	assertEqual(t, d.IP.String(), "::1")
	assertEqual(t, d.Port, uint16(8080))
}

func TestParseClose(t *testing.T) {
	b, err := ioutil.ReadFile(binDir + "close.bin")
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewBuffer(b)
	f, err := unmarshalFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, f.Command, Close)
	assertEqual(t, f.ID, uint32(6))
}

func TestParseShutdown(t *testing.T) {
	b, err := ioutil.ReadFile(binDir + "shutdown.bin")
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewBuffer(b)
	f, err := unmarshalFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, f.Command, Shutdown)
	assertEqual(t, f.ID, uint32(7))
}

func TestParseData(t *testing.T) {
	b, err := ioutil.ReadFile(binDir + "data.bin")
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewBuffer(b)
	f, err := unmarshalFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, f.Command, Data)
	assertEqual(t, f.ID, uint32(8))
	d, err := unmarshalData(r)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, d.payloadlen, uint32(128))
}

func assertEqual(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Fatalf("%s != %s", a, b)
	}
}

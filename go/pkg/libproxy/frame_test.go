package libproxy

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"testing"
)

// By default this is intended to be run from the Dockerfile
var binDir = "../../test_inputs/"

func ParsePrint(t *testing.T, b []byte) {
	r := bytes.NewBuffer(b)
	f, err := unmarshalFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	var w bytes.Buffer
	if err := f.Write(&w); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, w.Bytes()) {
		fmt.Printf("b = %v\nw = %v\n", b, w.Bytes())
		t.Fatal("ParsePrint not equal")
	}
}

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
	o, err := f.Open()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Payload().(*OpenFrame); !ok {
		t.Fatal("not an *OpenFrame")
	}
	assertEqual(t, o.Connection, Dedicated)
	assertEqual(t, o.Destination.Proto, TCP)
	assertEqual(t, o.Destination.IP.String(), "127.0.0.1")
	assertEqual(t, o.Destination.Port, uint16(8080))
	ParsePrint(t, b)
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
	o, err := f.Open()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Payload().(*OpenFrame); !ok {
		t.Fatal("not an *OpenFrame")
	}
	assertEqual(t, o.Destination.Proto, UDP)
	assertEqual(t, o.Destination.IP.String(), "::1")
	assertEqual(t, o.Destination.Port, uint16(8080))
	ParsePrint(t, b)
}

func TestParseOpenMultiplexedUnix(t *testing.T) {
	b, err := ioutil.ReadFile(binDir + "open_multiplexed_unix_connection.bin")
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
	o, err := f.Open()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Payload().(*OpenFrame); !ok {
		t.Fatal("not an *OpenFrame")
	}
	assertEqual(t, o.Destination.Proto, Unix)
	assertEqual(t, o.Destination.Path, "/tmp/foo")
	ParsePrint(t, b)
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
	if _, ok := f.Payload().(*CloseFrame); !ok {
		t.Fatal("not an *CloseFrame")
	}
	ParsePrint(t, b)
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
	if _, ok := f.Payload().(*ShutdownFrame); !ok {
		t.Fatal("not an *ShutdownFrame")
	}
	ParsePrint(t, b)
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
	d, err := f.Data()
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, d.payloadlen, uint32(128))
	if _, ok := f.Payload().(*DataFrame); !ok {
		t.Fatal("not an *DataFrame")
	}
	ParsePrint(t, b)
}

func TestParseWindow(t *testing.T) {
	b, err := ioutil.ReadFile(binDir + "window.bin")
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewBuffer(b)
	f, err := unmarshalFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, f.Command, Window)
	assertEqual(t, f.ID, uint32(9))
	w, err := f.Window()
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, w.seq, uint64(8888888))
	if _, ok := f.Payload().(*WindowFrame); !ok {
		t.Fatal("not an *WindowFrame")
	}
	ParsePrint(t, b)
}

func assertEqual(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Fatalf("%s != %s", a, b)
	}
}

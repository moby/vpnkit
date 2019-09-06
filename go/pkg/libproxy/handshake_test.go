package libproxy

import (
	"bytes"
	"testing"
)

func TestHandshakePrintParse(t *testing.T) {
	var w bytes.Buffer
	h := &handshake{
		payload: []byte("this is some payload"),
	}
	if err := h.Write(&w); err != nil {
		t.Fatal(err)
	}
	h2, err := unmarshalHandshake(&w)
	if err != nil {
		t.Fatal(err)
	}
	if string(h.payload) != string(h2.payload) {
		t.Fatalf("expected '%s' got '%s", string(h.payload), string(h2.payload))
	}
}

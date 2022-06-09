package libproxy

import (
	"io"
	"testing"
)

func TestWrite(t *testing.T) {
	// Check that writes don't block
	l := NewLoopback()
	n, err := l.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, 5, n)
}

func TestWriteRead(t *testing.T) {
	// Check that read works after write
	local := NewLoopback()
	n, err := local.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, 5, n)
	remote := local.OtherEnd()
	output := make([]byte, 5)
	n, err = remote.Read(output)
	assertEqual(t, 5, n)
	assertEqual(t, "hello", string(output))
}

func TestWriteCloseWriteRead(t *testing.T) {
	// test that write, closewrite, read doesn't drop data
	local := NewLoopback()
	n, err := local.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, 5, n)
	err = local.CloseWrite()
	if err != nil {
		t.Fatal(err)
	}
	remote := local.OtherEnd()
	output := make([]byte, 5)
	n, err = remote.Read(output)
	assertEqual(t, 5, n)
	assertEqual(t, "hello", string(output))
	n, err = remote.Read(output)
	assertEqual(t, 0, n)
	assertEqual(t, io.EOF, err)
}

func TestWriteCloseRead(t *testing.T) {
	// test that write, closewrite, read doesn't drop data
	local := NewLoopback()
	n, err := local.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, 5, n)
	err = local.Close()
	if err != nil {
		t.Fatal(err)
	}
	remote := local.OtherEnd()
	output := make([]byte, 5)
	n, err = remote.Read(output)
	assertEqual(t, 5, n)
	assertEqual(t, "hello", string(output))
	n, err = remote.Read(output)
	assertEqual(t, 0, n)
	assertEqual(t, io.EOF, err)
}

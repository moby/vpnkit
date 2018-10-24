package libproxy

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	loopback := newLoopback()
	local := NewMultiplexer("local", loopback)
	local.Run()
	remote := NewMultiplexer("remote", loopback.OtherEnd())
	remote.Run()
	client, err := local.Dial(Destination{
		Proto: TCP,
		IP:    net.ParseIP("127.0.0.1"),
		Port:  8080,
	})
	if err != nil {
		t.Fatal(err)
	}
	server, _, err := remote.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestClose(t *testing.T) {
	loopback := newLoopback()
	local := NewMultiplexer("local", loopback)
	local.Run()
	remote := NewMultiplexer("remote", loopback.OtherEnd())
	remote.Run()
	// There was a bug where the second iteration failed because the main loop had deadlocked
	// when it received a Close message.
	for i := 0; i < 2; i++ {
		client, err := local.Dial(Destination{
			Proto: TCP,
			IP:    net.ParseIP("127.0.0.1"),
			Port:  8080,
		})
		if err != nil {
			t.Fatal(err)
		}
		server, _, err := remote.Accept()
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		if err := server.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReadDeadline(t *testing.T) {
	loopback := newLoopback()
	local := NewMultiplexer("local", loopback)
	local.Run()
	remote := NewMultiplexer("remote", loopback.OtherEnd())
	remote.Run()
	client, err := local.Dial(Destination{
		Proto: TCP,
		IP:    net.ParseIP("127.0.0.1"),
		Port:  8080,
	})
	if err != nil {
		t.Fatal(err)
	}
	server, _, err := remote.Accept()
	if err != nil {
		t.Fatal(err)
	}
	// Server never writes
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var b []byte
	if _, err := client.Read(b); err == nil {
		t.Fatalf("Read should have timed out")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWriteDeadline(t *testing.T) {
	loopback := newLoopback()
	local := NewMultiplexer("local", loopback)
	local.Run()
	remote := NewMultiplexer("remote", loopback.OtherEnd())
	remote.Run()
	client, err := local.Dial(Destination{
		Proto: TCP,
		IP:    net.ParseIP("127.0.0.1"),
		Port:  8080,
	})
	if err != nil {
		t.Fatal(err)
	}
	server, _, err := remote.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if err := server.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error)
	go func() {
		buf, _ := genRandomBuffer(1024)
		for {
			if _, err := server.Write(buf); err != nil {
				done <- err
			}
		}
	}()
	// Client never reads so the window should close
	<-done
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

func genRandomBuffer(size int) ([]byte, string) {
	buf := make([]byte, size)
	_, _ = rand.Read(buf)
	return buf, fmt.Sprintf("% x", sha1.Sum(buf))
}

func writeRandomBuffer(w Conn, toWriteClient int) (chan error, string) {
	clientWriteBuf, clientWriteSha := genRandomBuffer(toWriteClient)
	done := make(chan error)

	go func() {
		if _, err := w.Write(clientWriteBuf); err != nil {
			done <- err
		}
		done <- w.CloseWrite()
	}()
	return done, clientWriteSha
}

func readAndSha(t *testing.T, r Conn) chan string {
	result := make(chan string)
	go func() {
		var toRead bytes.Buffer
		_, err := io.Copy(&toRead, r)
		if err != nil {
			t.Error(err)
		}
		sha := fmt.Sprintf("% x", sha1.Sum(toRead.Bytes()))
		result <- sha
	}()
	return result
}

func muxReadWrite(t *testing.T, toWriteClient, toWriteServer int) {
	loopback := newLoopback()
	local := NewMultiplexer("local", loopback)
	local.Run()
	remote := NewMultiplexer("other", loopback.OtherEnd())
	remote.Run()
	client, err := local.Dial(Destination{
		Proto: TCP,
		IP:    net.ParseIP("127.0.0.1"),
		Port:  8080,
	})
	if err != nil {
		t.Fatal(err)
	}
	clientWriteErr, clientWriteSha := writeRandomBuffer(client, toWriteClient)

	server, _, err := remote.Accept()
	if err != nil {
		t.Fatal(err)
	}

	serverWriteErr, serverWriteSha := writeRandomBuffer(server, toWriteServer)

	serverReadShaC := readAndSha(t, server)
	clientReadShaC := readAndSha(t, client)
	serverReadSha := <-serverReadShaC
	clientReadSha := <-clientReadShaC
	assertEqual(t, clientWriteSha, serverReadSha)
	assertEqual(t, serverWriteSha, clientReadSha)

	if err := <-clientWriteErr; err != nil {
		t.Fatal(err)
	}
	if err := <-serverWriteErr; err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

var (
	interesting = []int{
		0,
		1,
		4,
		4095,
		4096,
		4097,
		4098,
		4099,
		5000,
		5001,
		5002,
		1048575,
		1048576,
		1048577,
	}
)

func TestMuxCorners(t *testing.T) {
	for _, toWriteClient := range interesting {
		for _, toWriteServer := range interesting {
			log.Printf("Client will write %d and server will write %d", toWriteClient, toWriteServer)
			muxReadWrite(t, toWriteClient, toWriteServer)
		}
	}
}

func TestMuxReadWrite(t *testing.T) {
	muxReadWrite(t, 1048576, 1048576)
}

func TestMuxConcurrent(t *testing.T) {
	loopback := newLoopback()
	local := NewMultiplexer("local", loopback)
	local.Run()
	remote := NewMultiplexer("other", loopback.OtherEnd())
	remote.Run()

	numConcurrent := 1000
	toWrite := 65536 * 2 // 2 * Window size
	wg := &sync.WaitGroup{}
	serverWriteSha := make(map[uint16]string)
	serverReadSha := make(map[uint16]string)
	clientWriteSha := make(map[uint16]string)
	clientReadSha := make(map[uint16]string)
	m := &sync.Mutex{}
	wg.Add(numConcurrent)
	for i := 0; i < numConcurrent; i++ {
		go func(i int) {
			defer wg.Done()
			server, destination, err := remote.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			done, sha := writeRandomBuffer(server, toWrite)
			m.Lock()
			serverWriteSha[destination.Port] = sha
			m.Unlock()

			shaC := readAndSha(t, server)
			sha = <-shaC
			m.Lock()
			serverReadSha[destination.Port] = sha
			m.Unlock()

			if err := <-done; err != nil {
				t.Error(err)
			}
		}(i)
	}

	wg.Add(numConcurrent)
	for i := uint16(0); i < uint16(numConcurrent); i++ {
		go func(i uint16) {
			defer wg.Done()
			client, err := local.Dial(Destination{
				Proto: TCP,
				IP:    net.ParseIP("127.0.0.1"),
				Port:  i,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			done, sha := writeRandomBuffer(client, toWrite)
			m.Lock()
			clientWriteSha[i] = sha
			m.Unlock()

			shaC := readAndSha(t, client)
			sha = <-shaC
			m.Lock()
			clientReadSha[i] = sha
			m.Unlock()
			if err := <-done; err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	failed := false
	for i := uint16(0); i < uint16(numConcurrent); i++ {
		if clientWriteSha[i] != serverReadSha[i] {
			fmt.Printf("clientWriteSha[%d] = %s\nserverReadSha[%d] = %s\n", i, clientWriteSha[i], i, serverReadSha[i])
			failed = true
		}
		if serverWriteSha[i] != clientReadSha[i] {
			fmt.Printf("serverWriteSha[%d] = %s\nclientReadSha[%d] = %s\n", i, serverWriteSha[i], i, clientReadSha[i])
			failed = true
		}
	}
	if failed {
		t.Errorf("SHA mismatch")
	}
}

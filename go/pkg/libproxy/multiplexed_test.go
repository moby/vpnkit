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

func TestCloseClose(t *testing.T) {
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
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		if err := server.Close(); err != nil {
			t.Fatal(err)
		}
		if !remote.IsRunning() {
			t.Fatal("remote multiplexer has failed")
		}
	}
}

func TestCloseWriteCloseWrite(t *testing.T) {
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
		if err := client.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if err := client.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if err := server.Close(); err != nil {
			t.Fatal(err)
		}
		if !remote.IsRunning() {
			t.Fatal("remote multiplexer has failed")
		}
	}
}

func TestCloseCloseWrite(t *testing.T) {
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
		if err := client.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if err := server.Close(); err != nil {
			t.Fatal(err)
		}
		if !remote.IsRunning() {
			t.Fatal("remote multiplexer has failed")
		}
	}
}

func TestCloseThenWrite(t *testing.T) {
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
		loopback.simulateLatency = time.Second
		done := make(chan struct{})
		go func() {
			for {
				if _, err := client.Write([]byte{1}); err != nil {
					close(done)
					return // EOF
				}
			}
		}()
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		<-done
		if !remote.IsRunning() {
			t.Fatal("remote multiplexer has failed")
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
	done := make(chan error, 1)

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

func muxReadWrite(t *testing.T, local, remote *Multiplexer, toWriteClient, toWriteServer int) {
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
			loopback := newLoopback()
			local := NewMultiplexer("local", loopback)
			local.Run()
			remote := NewMultiplexer("other", loopback.OtherEnd())
			remote.Run()
			muxReadWrite(t, local, remote, toWriteClient, toWriteServer)
		}
	}
}

func TestMuxReadWrite(t *testing.T) {
	loopback := newLoopback()
	local := NewMultiplexer("local", loopback)
	local.Run()
	remote := NewMultiplexer("other", loopback.OtherEnd())
	remote.Run()
	muxReadWrite(t, local, remote, 1048576, 1048576)
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

func writeAndBlock(t *testing.T, local, remote *Multiplexer) chan error {
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
	if err := server.SetWriteDeadline(time.Now().Add(1 * time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		buf, _ := genRandomBuffer(1024)
		for {
			// Client never reads so the window should close
			if _, err := server.Write(buf); err != nil {
				fmt.Printf("server.Write failed with %v", err)
				break
			}
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		if err := server.Close(); err != nil {
			t.Fatal(err)
		}
		close(done)
	}()
	// (hack) wait until the window must be full and the Write is blocked
	time.Sleep(500 * time.Millisecond)
	return done
}

func TestWindow(t *testing.T) {
	// Check that one connection blocked on a window update doesn't preclude
	// other connections from working i.e. the lowlevel connection handler isn't
	// itself blocked in a write()
	loopback := newLoopback()
	local := NewMultiplexer("local", loopback)
	local.Run()
	remote := NewMultiplexer("remote", loopback.OtherEnd())
	remote.Run()

	done := writeAndBlock(t, local, remote)
	// The first connection should have blocked and the window should be closed for another 500ms
	muxReadWrite(t, local, remote, 1048576, 1048576)

	select {
	case <-done:
		t.Fatalf("the second connection was blocked by the first")
	default:
		fmt.Println("second connection completed while the first was blocked")
		<-done
		fmt.Println("first connection has now unblocked")
	}
}

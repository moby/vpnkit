package libproxy

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// create a pair of connected multiplexers
func newLoopbackMultiplexer(t *testing.T, loopback *loopback) (Multiplexer, Multiplexer) {
	localMuxC, localErrC := newMultiplexer("local", loopback, false)
	remoteMuxC, remoteErrC := newMultiplexer("remote", loopback.OtherEnd(), true)
	if err := <-localErrC; err != nil {
		t.Fatal(err)
	}
	if err := <-remoteErrC; err != nil {
		t.Fatal(err)
	}
	local := <-localMuxC
	remote := <-remoteMuxC
	local.Run()
	remote.Run()
	return local, remote
}

// start a multiplexer asynchronously
func newMultiplexer(name string, conn io.ReadWriteCloser, allocateBackwards bool) (<-chan Multiplexer, <-chan error) {
	m := make(chan Multiplexer)
	e := make(chan error)
	go func() {
		mux, err := NewMultiplexer(name, conn, allocateBackwards)
		e <- err
		m <- mux
	}()
	return m, e
}

func TestNew(t *testing.T) {
	loopback := NewLoopback()
	local, remote := newLoopbackMultiplexer(t, loopback)
	client, err := local.Dial(Destination{
		Proto: TCP,
		IP:    net.ParseIP("127.0.0.1"),
		Port:  8080,
	})
	require.Nil(t, err)
	server, _, err := remote.Accept()
	require.Nil(t, err)
	assert.Nil(t, client.Close())
	assert.Nil(t, server.Close())
	assert.Nil(t, local.Close())
	assert.Nil(t, remote.Close())
}

func TestClose(t *testing.T) {
	loopback := NewLoopback()
	local, remote := newLoopbackMultiplexer(t, loopback)
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

func TestUDPEncapsulationIsTransparent(t *testing.T) {
	loopback := NewLoopback()
	local, remote := newLoopbackMultiplexer(t, loopback)

	client, err := local.Dial(Destination{
		Proto: UDP,
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
	message := []byte("hello world")
	n, err := client.Write(message)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(message) {
		t.Fatal("Failed to send whole message")
	}
	buf := make([]byte, 1024)
	n, err = server.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(message) {
		t.Fatalf("Failed to read whole message, read %d expected %d", n, len(message))
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCloseClose(t *testing.T) {
	loopback := NewLoopback()
	local, remote := newLoopbackMultiplexer(t, loopback)
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
	loopback := NewLoopback()
	local, remote := newLoopbackMultiplexer(t, loopback)
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
	loopback := NewLoopback()
	local, remote := newLoopbackMultiplexer(t, loopback)
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

func TestCloseWriteWrite(t *testing.T) {
	loopback := NewLoopback()
	local, remote := newLoopbackMultiplexer(t, loopback)
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
	channel, ok := client.(*channel)
	if !ok {
		t.Fatal("conn was not a *channel")
	}
	channel.setTestAllowDataAfterCloseWrite()
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	// FIXME: need a way to wait for the multiplexer to have processed the message.
	time.Sleep(time.Second)
	if !remote.IsRunning() {
		t.Fatal("remote multiplexer has failed")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCloseThenWrite(t *testing.T) {
	loopback := NewLoopback()
	local, remote := newLoopbackMultiplexer(t, loopback)
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
	loopback := NewLoopback()
	local, remote := newLoopbackMultiplexer(t, loopback)
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
	loopback := NewLoopback()
	local, remote := newLoopbackMultiplexer(t, loopback)
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

func muxReadWrite(t *testing.T, local, remote Multiplexer, toWriteClient, toWriteServer int) {
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
			loopback := NewLoopback()
			local, remote := newLoopbackMultiplexer(t, loopback)
			muxReadWrite(t, local, remote, toWriteClient, toWriteServer)
		}
	}
}

func TestMuxReadWrite(t *testing.T) {
	loopback := NewLoopback()
	local, remote := newLoopbackMultiplexer(t, loopback)
	muxReadWrite(t, local, remote, 1048576, 1048576)
}

func TestMuxConcurrent(t *testing.T) {
	loopback := NewLoopback()
	local, remote := newLoopbackMultiplexer(t, loopback)
	numConcurrent := 500 // limited by the race detector
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
			// Set the read/write buffer sizes to unusual values.
			server.SetReadBuffer(defaultWindowSize - 1)
			server.SetWriteBuffer(defaultWindowSize - 1)
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

func writeAndBlock(t *testing.T, local, remote Multiplexer) chan error {
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
	loopback := NewLoopback()
	local, remote := newLoopbackMultiplexer(t, loopback)

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

func TestEOF(t *testing.T) {
	loopback := NewLoopback()
	if err := loopback.OtherEnd().Close(); err != nil {
		t.Fatal(err)
	}
	_, err := NewMultiplexer("test", loopback, false)
	if err != io.EOF {
		t.Fatal(err)
	}
}

func TestCrossChannelOpening(t *testing.T) {
	loopback := NewLoopback()
	muxHost, muxGuest := newLoopbackMultiplexer(t, loopback)
	acceptG := &errgroup.Group{}
	acceptG.Go(func() error {
		for {
			c, _, err := muxHost.Accept()
			if err != nil {
				return err
			}
			var m int32
			if err := binary.Read(c, binary.LittleEndian, &m); err != nil {
				return err
			}
			if err := binary.Write(c, binary.LittleEndian, m); err != nil {
				return err
			}
			_ = c.Close()
		}
	})
	acceptG.Go(func() error {
		for {
			c, _, err := muxGuest.Accept()
			if err != nil {
				return err
			}
			var m int32
			if err := binary.Read(c, binary.LittleEndian, &m); err != nil {
				return err
			}
			if err := binary.Write(c, binary.LittleEndian, m); err != nil {
				return err
			}
			_ = c.Close()
		}
	})
	g := &errgroup.Group{}
	for i := 0; i < 20; i++ {
		g.Go(func() error {
			c, err := muxHost.Dial(Destination{Proto: Unix, Path: "/test"})
			if err != nil {
				return err
			}
			m := int32(42)

			if err := binary.Write(c, binary.LittleEndian, m); err != nil {
				return err
			}
			if err := binary.Read(c, binary.LittleEndian, &m); err != nil {
				return err
			}
			_ = c.Close()
			log.Print("muxHost negociation succeeded")
			return nil
		})
		g.Go(func() error {
			c, err := muxGuest.Dial(Destination{Proto: Unix, Path: "/test"})
			if err != nil {
				return err
			}
			m := int32(42)

			if err := binary.Write(c, binary.LittleEndian, m); err != nil {
				return err
			}
			if err := binary.Read(c, binary.LittleEndian, &m); err != nil {
				return err
			}
			_ = c.Close()
			log.Print("muxGuest negociation succeeded")
			return nil
		})
	}
	_ = g.Wait()
}

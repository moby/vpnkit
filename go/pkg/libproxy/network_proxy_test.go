package libproxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

var testBuf = []byte("Buffalo buffalo Buffalo buffalo buffalo buffalo Buffalo buffalo")
var testBufSize = len(testBuf)

type EchoServer interface {
	Run()
	Close()
	LocalAddr() net.Addr
}

type StreamEchoServer struct {
	listener net.Listener
	testCtx  *testing.T
}

type UDPEchoServer struct {
	conn    net.PacketConn
	testCtx *testing.T
}

func NewEchoServer(t *testing.T, proto, address string) EchoServer {
	var server EchoServer
	if strings.HasPrefix(proto, "tcp") || strings.HasPrefix(proto, "unix") {
		listener, err := net.Listen(proto, address)
		if err != nil {
			t.Fatal(err)
		}
		server = &StreamEchoServer{listener: listener, testCtx: t}
	} else {
		socket, err := net.ListenPacket(proto, address)
		if err != nil {
			t.Fatal(err)
		}
		server = &UDPEchoServer{conn: socket, testCtx: t}
	}
	return server
}

func (server *StreamEchoServer) Run() {
	go func() {
		for {
			client, err := server.listener.Accept()
			if err != nil {
				return
			}
			go func(client net.Conn) {
				if _, err := io.Copy(client, client); err != nil {
					server.testCtx.Logf("can't echo to the client: %v\n", err.Error())
				}
				client.Close()
			}(client)
		}
	}()
}

func (server *StreamEchoServer) LocalAddr() net.Addr { return server.listener.Addr() }
func (server *StreamEchoServer) Close()              { server.listener.Addr() }

func (server *UDPEchoServer) Run() {
	go func() {
		readBuf := make([]byte, 1024)
		for {
			read, from, err := server.conn.ReadFrom(readBuf)
			if err != nil {
				return
			}
			for i := 0; i != read; {
				written, err := server.conn.WriteTo(readBuf[i:read], from)
				if err != nil {
					break
				}
				i += written
			}
		}
	}()
}

func (server *UDPEchoServer) LocalAddr() net.Addr { return server.conn.LocalAddr() }
func (server *UDPEchoServer) Close()              { server.conn.Close() }

func testProxyAt(t *testing.T, proto string, proxy Proxy, addr string) {
	defer proxy.Close()
	go proxy.Run()
	log.Printf("Proxy forwarding from %s -> %s\n", proxy.FrontendAddr().String(), proxy.BackendAddr().String())
	log.Printf("Dial(%s, %s)\n", proto, addr)
	client, err := net.Dial(proto, addr)
	if err != nil {
		t.Fatalf("Can't connect to the proxy: %v", err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = client.Write(testBuf); err != nil {
		t.Fatal(err)
	}
	recvBuf := make([]byte, testBufSize)
	if _, err = client.Read(recvBuf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(testBuf, recvBuf) {
		t.Fatal(fmt.Errorf("Expected [%v] but got [%v]", testBuf, recvBuf))
	}
}

func testProxy(t *testing.T, proto string, proxy Proxy) {
	testProxyAt(t, proto, proxy, proxy.FrontendAddr().String())
}

func TestUnixProxy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix domain sockets don't work on Windows")
	}
	pathA := "/tmp/network_proxy_test.sock"
	pathB := "/tmp/network_proxy_test.sock2"
	if err := os.Remove(pathA); err != nil && !(os.IsNotExist(err)) {
		t.Fatal(err)
	}
	if err := os.Remove(pathB); err != nil && !(os.IsNotExist(err)) {
		t.Fatal(err)
	}
	backend := NewEchoServer(t, "unix", pathA)
	defer backend.Close()
	backend.Run()
	log.Printf("Running an echo server on %s\n", backend.LocalAddr().String())
	frontendAddr, err := net.ResolveUnixAddr("unix", pathB)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := NewIPProxy(frontendAddr, backend.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	testProxy(t, "unix", proxy)
}

func TestTCP4Proxy(t *testing.T) {
	backend := NewEchoServer(t, "tcp", "127.0.0.1:0")
	defer backend.Close()
	backend.Run()
	frontendAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	proxy, err := NewIPProxy(frontendAddr, backend.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	testProxy(t, "tcp", proxy)
}

func TestTCP6Proxy(t *testing.T) {
	t.Skip("No support for IPv6 inside Docker")
	backend := NewEchoServer(t, "tcp", "[::1]:0")
	defer backend.Close()
	backend.Run()
	frontendAddr := &net.TCPAddr{IP: net.IPv6loopback, Port: 0}
	proxy, err := NewIPProxy(frontendAddr, backend.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	testProxy(t, "tcp", proxy)
}

func TestTCPDualStackProxy(t *testing.T) {
	// If I understand `godoc -src net favoriteAddrFamily` (used by the
	// net.Listen* functions) correctly this should work, but it doesn't.
	t.Skip("No support for dual stack yet")
	backend := NewEchoServer(t, "tcp", "[::1]:0")
	defer backend.Close()
	backend.Run()
	frontendAddr := &net.TCPAddr{IP: net.IPv6loopback, Port: 0}
	proxy, err := NewIPProxy(frontendAddr, backend.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	ipv4ProxyAddr := &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: proxy.FrontendAddr().(*net.TCPAddr).Port,
	}
	testProxyAt(t, "tcp", proxy, ipv4ProxyAddr.String())
}

func TestUDP4Proxy(t *testing.T) {
	backend := NewEchoServer(t, "udp", "127.0.0.1:0")
	defer backend.Close()
	backend.Run()
	frontendAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	proxy, err := NewIPProxy(frontendAddr, backend.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	testProxy(t, "udp", proxy)
}

func TestUDP6Proxy(t *testing.T) {
	t.Skip("No support for IPv6 inside Docker")
	backend := NewEchoServer(t, "udp", "[::1]:0")
	defer backend.Close()
	backend.Run()
	frontendAddr := &net.UDPAddr{IP: net.IPv6loopback, Port: 0}
	proxy, err := NewIPProxy(frontendAddr, backend.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	testProxy(t, "udp", proxy)
}

func TestUDPWriteError(t *testing.T) {
	frontendAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	// Normally we would automatically choose a free port for the backend
	// server but we specifically want to check what happens when the server
	// is not running. This means we have to pick a port in advance.
	// Hopefully, this port will be free:
	port := 25587
	backendAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	proxy, err := NewIPProxy(frontendAddr, backendAddr)
	if err != nil {
		t.Fatal(err)
	}
	frontendAddr = proxy.FrontendAddr().(*net.UDPAddr)

	defer proxy.Close()
	go proxy.Run()
	client, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", frontendAddr.Port))
	if err != nil {
		t.Fatalf("Can't connect to the proxy: %v", err)
	}
	defer client.Close()

	// Make sure the proxy doesn't stop when there is no actual backend:
	if _, err = client.Write(testBuf); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Write(testBuf); err != nil {
		t.Fatal(err)
	}
	backend := NewEchoServer(t, "udp", fmt.Sprintf("127.0.0.1:%d", port))
	defer backend.Close()
	backend.Run()
	client.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = client.Write(testBuf); err != nil {
		t.Fatal(err)
	}
	recvBuf := make([]byte, testBufSize)
	if _, err = client.Read(recvBuf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(testBuf, recvBuf) {
		t.Fatal(fmt.Errorf("Expected [%v] but got [%v]", testBuf, recvBuf))
	}
}

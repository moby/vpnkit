package forward

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/moby/vpnkit/go/pkg/libproxy"
	"github.com/moby/vpnkit/go/pkg/vpnkit/log"
	"github.com/pkg/errors"
)

func listenTCPVmnet(IP net.IP, Port uint16) (net.Listener, error) {
	newFD, err := listenVmnet(IP, Port, true)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(newFD, fmt.Sprintf("tcp:%s:%d", IP, Port))
	defer f.Close()
	return net.FileListener(f)
}

func listenUDPVmnet(IP net.IP, Port uint16) (libproxy.UDPListener, error) {
	localAddress := &net.UDPAddr{
		IP:   IP,
		Port: int(Port),
	}
	newFD, err := listenVmnet(IP, Port, false)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(newFD, fmt.Sprintf("udp:%s:%d", IP, Port))
	defer f.Close()
	c, err := net.FilePacketConn(f)
	if err != nil {
		return nil, err
	}
	return udpPacketConnWrapper{c, localAddress}, nil
}

type udpPacketConnWrapper struct {
	c         net.PacketConn
	localAddr net.Addr
}

func (u udpPacketConnWrapper) Close() error {
	return u.c.Close()
}

func (u udpPacketConnWrapper) LocalAddr() net.Addr {
	return u.localAddr
}

func (u udpPacketConnWrapper) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	n, addr, err := u.c.ReadFrom(b)
	from, ok := addr.(*net.UDPAddr)
	if !ok {
		log.Printf("UDP packet from address %v was not a *net.UDPAddr", addr)
	}
	return n, from, err
}

func (u udpPacketConnWrapper) WriteToUDP(b []byte, to *net.UDPAddr) (int, error) {
	return u.c.WriteTo(b, to)
}

func listenVmnet(IP net.IP, Port uint16, TCP bool) (uintptr, error) {
	conn, err := sendCommand(bindIpv4Command)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	b := bindIpv4{
		IP, Port, TCP,
	}
	if err := writeBindIpv4(conn, b); err != nil {
		return 0, err
	}
	return readResult(conn)
}

const (
	bindIpv4Command = 6

	// currentVersion is the current vmnetd version
	currentVersion = 22
)

const (
	vmnetdSocketPath = "/var/run/com.docker.vmnetd.sock"

	oldHello = "VMNET"
	hello    = "VMN3T"
)

// bindIpv4 is a request to bind a (probably privileged) TCP or UDP port.
type bindIpv4 struct {
	IP   net.IP // only IPv4
	Port uint16
	TCP  bool // or udp
}

// writeBindIpv4 writes a BindIpv4 requst.
func writeBindIpv4(w io.Writer, b bindIpv4) error {
	ipv4 := b.IP.To4()
	bytes := []byte{ipv4[3], ipv4[2], ipv4[1], ipv4[0]}
	if _, err := w.Write(bytes); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, b.Port); err != nil {
		return err
	}
	tcp := uint8(1)
	if b.TCP {
		tcp = uint8(0)
	}
	return binary.Write(w, binary.LittleEndian, tcp)

}

// readBindIpv4 reads a bindIpv4 request.
func readBindIpv4(r io.Reader) (*bindIpv4, error) {
	msg := &bindIpv4{}

	ipv4 := make([]byte, 4)
	if _, err := r.Read(ipv4); err != nil {
		return nil, err
	}
	msg.IP = net.IPv4(ipv4[3], ipv4[2], ipv4[1], ipv4[0])
	if err := binary.Read(r, binary.LittleEndian, &msg.Port); err != nil {
		return nil, err
	}
	tcp := uint8(0)
	if err := binary.Read(r, binary.LittleEndian, &tcp); err != nil {
		return nil, err
	}
	switch tcp {
	case 0:
		msg.TCP = true
	case 1:
		msg.TCP = false
	default:
		return nil, errors.New("unknown stream/tcp value")
	}
	return msg, nil
}

func sendCommand(code int) (*net.UnixConn, error) {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{
		vmnetdSocketPath,
		"unix",
	})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect to %s: is vmnetd running?", vmnetdSocketPath)
	}
	if err := performClient(conn, code); err != nil {
		conn.Close()
		return nil, errors.Wrapf(err, "handshake failed")
	}
	return conn, nil
}

func readResult(conn *net.UnixConn) (uintptr, error) {
	unixConnFile, err := conn.File()
	if err != nil {
		return 0, errors.Wrap(err, "can't access connection file")
	}
	defer unixConnFile.Close()

	unixConnFd := int(unixConnFile.Fd())
	results := make([]byte, 100)
	oob := make([]byte, syscall.CmsgSpace(1*4))
	n, _, _, _, err := syscall.Recvmsg(unixConnFd, results, oob, 0)
	if err != nil {
		return 0, errors.Wrap(err, "failed to receive message")
	}

	code := uint8(0)
	buf := bytes.NewBuffer(results[0:n])
	if err := binary.Read(buf, binary.LittleEndian, &code); err != nil {
		return 0, errors.Wrapf(err, "failed to read result")
	}
	switch code {
	case 0:
		var msgs []syscall.SocketControlMessage
		msgs, err = syscall.ParseSocketControlMessage(oob)
		if err != nil {
			return 0, err
		}
		if len(msgs) != 1 {
			return 0, errors.New("no file descriptor")
		}
		fds, err := syscall.ParseUnixRights(&msgs[0])
		if err != nil {
			return 0, err
		}
		if len(fds) != 1 {
			return 0, errors.New("array of fds was empty")
		}
		return uintptr(fds[0]), nil
	case 48:
		return 0, errors.New("port is already allocated.")
	case 49:
		return 0, errors.New("bind: cannot assign requested address.")
	case 1:
		return 0, errors.New("command failed")
	default:
		return 0, errors.New("failed to unmarshal command result")
	}
}

// performClient performs the connection handshake as a client and sends a command.
func performClient(conn net.Conn, command int) error {
	err := writeInitMessage(conn, getOutgoingMessage())
	if err != nil {
		return errors.Wrap(err, "cannot send handshake message")
	}
	if _, err := readInitMessage(conn); err != nil {
		return err
	}
	return writeCommand(conn, command)
}

type handshakeMessage struct {
	Hello   string // char[5]
	Version uint32 // uint32_t
	Commit  string // char[40]
}

func getOutgoingMessage() *handshakeMessage {
	return &handshakeMessage{
		Hello:   hello,
		Version: currentVersion,
		Commit:  "0d4854a28a379fbe8341b753ae2eb05fc3446f38",
	}
}

func readInitMessage(conn io.Reader) (*handshakeMessage, error) {
	msg := &handshakeMessage{}

	hello, err := readBytes(conn, 5)
	if err != nil {
		return nil, err
	}
	msg.Hello = string(hello)

	// old version only had this in handshake data, so we stop reading
	if msg.Hello == oldHello {
		msg.Version = 0
		return msg, nil
	}

	versionBytes, err := readBytes(conn, 4)
	if err != nil {
		return nil, err
	}
	version, byteCount := binary.Uvarint(versionBytes)
	if byteCount <= 0 {
		return nil, errors.New("Could not parse version")
	}
	msg.Version = uint32(version)

	commit, err := readBytes(conn, 40)
	if err != nil {
		return nil, err
	}
	msg.Commit = string(commit)

	return msg, nil
}

func writeInitMessage(conn io.Writer, msg *handshakeMessage) error {

	// hello
	if _, err := conn.Write([]byte(msg.Hello)); err != nil {
		return err
	}

	// version
	vb := make([]byte, 4)
	binary.PutUvarint(vb, uint64(msg.Version))
	if _, err := conn.Write(vb); err != nil {
		return err
	}

	// commit
	if _, err := conn.Write([]byte(msg.Commit)); err != nil {
		return err
	}

	return nil
}

func readCommand(conn io.Reader) (int, error) {
	var command = make([]byte, 1)
	if _, err := conn.Read(command); err != nil {
		return -1, err
	}
	return int(command[0]), nil
}

func writeCommand(conn io.Writer, command int) error {
	b := int8(command)
	return binary.Write(conn, binary.LittleEndian, &b)
}

func readBytes(conn io.Reader, length int) ([]byte, error) {
	b := make([]byte, length)
	if _, err := conn.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func isPermissionDenied(err error) bool {
	return strings.HasSuffix(err.Error(), "permission denied")
}

package vmnet

import (
	"net"
	"time"
)

// dhcp queries the IP by DHCP
func dhcpRequest(packet sendReceiver, clientMAC net.HardwareAddr) (net.IP, error) {
	broadcastMAC := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	broadcastIP := []byte{0xff, 0xff, 0xff, 0xff}
	unknownIP := []byte{0, 0, 0, 0}

	dhcpRequest := NewDhcpRequest(clientMAC).Bytes()
	ipv4 := NewIpv4(broadcastIP, unknownIP)

	udpv4 := NewUdpv4(ipv4, 68, 67, dhcpRequest)
	ipv4.setData(udpv4.Bytes())

	ethernet := NewEthernetFrame(broadcastMAC, clientMAC, 0x800)
	ethernet.setData(ipv4.Bytes())
	finished := false
	go func() {
		for !finished {
			if _, err := packet.Send(ethernet.Bytes()); err != nil {
				panic(err)
			}
			time.Sleep(time.Second)
		}
	}()

	buf := make([]byte, 1500)
	for {
		n, err := packet.Recv(buf)
		if err != nil {
			return nil, err
		}
		response := buf[0:n]
		ethernet, err = ParseEthernetFrame(response)
		if err != nil {
			continue
		}
		for i, x := range ethernet.Dst {
			if i > len(clientMAC) || clientMAC[i] != x {
				// intended for someone else
				continue
			}
		}
		ipv4, err = ParseIpv4(ethernet.Data)
		if err != nil {
			// probably not an IPv4 packet
			continue
		}
		udpv4, err = ParseUdpv4(ipv4.Data)
		if err != nil {
			// probably not a UDPv4 packet
			continue
		}
		if udpv4.Src != 67 || udpv4.Dst != 68 {
			// not a DHCP response
			continue
		}
		if len(udpv4.Data) < 243 {
			// truncated
			continue
		}
		if udpv4.Data[240] != 53 || udpv4.Data[241] != 1 || udpv4.Data[242] != 2 {
			// not a DHCP offer
			continue
		}
		var ip net.IP
		ip = udpv4.Data[16:20]
		finished = true // will terminate sending goroutine
		return ip, nil
	}
}

// DhcpRequest is a simple DHCP request
type DhcpRequest struct {
	MAC net.HardwareAddr
}

// NewDhcpRequest constructs a DHCP request
func NewDhcpRequest(MAC net.HardwareAddr) *DhcpRequest {
	if len(MAC) != 6 {
		panic("MAC address must be 6 bytes")
	}
	return &DhcpRequest{MAC}
}

// Bytes returns the marshalled DHCP request
func (d *DhcpRequest) Bytes() []byte {
	bs := []byte{
		0x01,                   // OP
		0x01,                   // HTYPE
		0x06,                   // HLEN
		0x00,                   // HOPS
		0x01, 0x00, 0x00, 0x00, // XID
		0x00, 0x00, // SECS
		0x80, 0x00, // FLAGS
		0x00, 0x00, 0x00, 0x00, // CIADDR
		0x00, 0x00, 0x00, 0x00, // YIADDR
		0x00, 0x00, 0x00, 0x00, // SIADDR
		0x00, 0x00, 0x00, 0x00, // GIADDR
		d.MAC[0], d.MAC[1], d.MAC[2], d.MAC[3], d.MAC[4], d.MAC[5],
	}
	bs = append(bs, make([]byte, 202)...)
	bs = append(bs, []byte{
		0x63, 0x82, 0x53, 0x63, // Magic cookie
		0x35, 0x01, 0x01, // DHCP discover
		0xff, // Endmark
	}...)
	return bs
}

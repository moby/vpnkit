# Using vpnkit as a default gateway

This page describes how `vpnkit` is used to provide a default gateway inside Docker
for Mac and Docker for Windows. We start by describing the
plumbing needed to extract ethernet frames from a Linux VM running on the Mac
and on Windows, and then describe the processing `vpnkit` performs on these
frames in order to provide the illusion of true Internet connectivity.

## Plumbing inside Docker for Mac

The Docker for Mac VM is running on top of the [hyperkit](https://github.com/moby/hyperkit)
hypervisor. The VM has a `virtio-vpnkit` PCI device which appears as a `virtio-net`
network interface inside the VM. The
[virtual hardware implementation](https://github.com/moby/hyperkit/blob/master/src/lib/pci_virtio_net_vpnkit.c) connects to
`vpnkit` on the host over a Unix domain socket and encapsulates frames using a
simple custom protocol.

![Mac plumbing diagram](http://moby.github.io/vpnkit/mac.png)

## Plumbing inside Docker for Windows

The Docker for Windows VM is running on top of Hyper-V. `vpnkit` on the host
uses Hyper-V sockets to connect to a process (`tap-vsockd`) inside the VM which accepts the
connection and configures a `tap` device. Frames are encapsulated using the
same custom protocol as on the Mac.

![Windows plumbing diagram](http://moby.github.io/vpnkit/win.png)

Note: the connection is currently made from the Host to the VM to work around
a bug in older versions of Windows 10. At some point this should change to be
a connection from the VM to the host.

Note: the userspace `tap-vsockd` process in the VM which configures a `tap` device could be
replaced with a custom Linux kernel driver which knows how to encapsulate the
frames and communicate over Hyper-V sockets.

## When a frame arrives in vpnkit

Frames arriving from the VM are processed by a simple internal ethernet switch.
The switch demultiplexes traffic onto output ports by matching on the destination
IPv4 address. Frames which don't match any rule are forwarded to a default port.

Frames arriving on the default port are examined and

- if they contain ARP requests, we send a response using a static global ARP
  table
- if they contain IPv4 datagrams then we create a fresh virtual TCP/IP endpoint
  using the [Mirage](https://mirage.io/) [TCP/IP stack](https://github.com/mirage/mirage-tcpip)
  (no kernel TCP/IP interfaces are involved), a fresh
  switch port on our internal switch and connect them together so that all future IPv4 traffic to the
  same destination address is processed by the new endpoint.

Each virtual TCP/IP endpoint terminates TCP and UDP flows using the
[Mirage](https://mirage.io/) [TCP/IP stack](https://github.com/mirage/mirage-tcpip).
The data from the flows is proxied to and from regular BSD-style sockets on
both Windows and Mac. The host kernel therefore only sees outgoing
`SOCK_STREAM` and `SOCK_DGRAM` connections from the `vpnkit` process.

If the VM is communicating with 10 remote IP addresses, then there will be 10
instances of a Mirage TCP/IP stack, one per IP address. The TCP/IP stack
instances act as proxies for the remote hosts.

The following diagram shows the flow of ethernet traffic within `vpnkit`:

![ethernet diagram](http://moby.github.io/vpnkit/ethernet.png)

Each switch port has an associated `last_active_time` and if there is no traffic
flow for a configured time interval, the port is deactivated and the TCP/IP
endpoint is shutdown.

The active ports may be queried by connecting to a Unix domain socket on the Mac
or a named pipe on Windows and receiving diagnostic data in a Unix tar formatted
stream.


## Example: connection setup

Consider what happens when an application inside a container in the Linux VM
tries to make a TCP connection:

- the application calls `connect`
- the Linux kernel emits a `TCP` packet with the `SYN` flag set
- the Linux kernel applies the `iptables` rules and consults
  the routing table to select the outgoing interface and then transmits the frame
- the frame is relayed to the host
  - on windows: the interface was a `tap` device created by the `tap-vsockd`
    process. This process reads the frame from the associated file descriptor,
    encapsulates it and writes it to the Hyper-V socket connected to `vpnkit`.
  - on Mac: the interface was a `virtio-net` NIC. The network driver in the VM pushes
    the packet to a queue in memory shared with the hypervisor, the `virtio-vpnkit`
    virtual hardware pops the packet from the queue and then writes it down a
    Unix domain socket connected to `vpnkit`.
- the frame is received by `vpnkit` and input into the ethernet switch.
  - if the destination IP is not recognised: `vpnkit` creates a TCP/IP endpoint
    using [Mirage](https://mirage.io/) [TCP/IP stack](https://github.com/mirage/mirage-tcpip)
    with the destination IP address and configures the switch to send future
    packets with this destination IP to this endpoint
  - if the destination IP is recognised: the internal switch inputs the frame
    into the TCP/IP endpoint
- the TCP/IP endpoint observes the `SYN` flag is set and so it calls the regular
  `connect` API to establish a regular `SOCK_STREAM` connection to that destination.
  - if the `connect` succeeds: the TCP/IP endpoint sends back a packet with the
    `SYN` and `ACK` flags set and the handshake continues
  - if the `connect` fails: the TCP/IP endpoint sends back a packet with the
    `RST` flag set to reject the connection.

If all has gone well, the VM now has a TCP connection over a virtual point-to-point
ethernet link connected to `vpnkit`, and `vpnkit` has a socket connection to
the true destination. `vpnkit` will now proxy the data in both directions.

Note that from the host kernel's point of view, there is no network connection
to the VM and no set of associated firewall rules or routing tables. All outgoing
connections originate from the `vpnkit` process. If the user installs some
advanced networking or VPN software which reconfigures the routing table or
firewall rules, it will not break the connection between `vpnkit` and the VM.

This technique for forwarding network connections is commonly known as
[Slirp](https://en.wikipedia.org/wiki/Slirp).

# Ethernet traffic flow

The following diagram shows the flow of ethernet traffic from the VM:

![ethernet diagram](http://moby.github.io/vpnkit/ethernet.png)

Frames arriving from the VM interface are processed by a simple ethernet switch.
The switch demultiplexes traffic onto output ports by matching against rules.
The current rules match only on the destination IPv4 address. Frames which
don't match any rule are forwarded to a default port.

Frames arriving on the default port are examined and

- if they contain ARP requests, we send a response using a static global ARP
  tabl
- if they contain IPv4 datagrams then we create a fresh TCP/IP stack, a fresh
  switch port and connect them together so that all future IPv4 traffic to the
  same destination address is processed by the new stack.

If the VM is communicating with 10 remote IP addresses, then there will be 10
instances of a Mirage TCP/IP stack, one per IP address. The TCP/IP stack
instances act as proxies for the remote hosts.

Each switch port has an associated `last_active_time` and if there is no traffic
flow for a configured time interval, the port is deactivated.

The active ports may be queried over the 9P debug interface via the `ports`
subdirectory.

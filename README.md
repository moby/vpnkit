VPN-friendly networking devices for [HyperKit](https://github.com/docker/hyperkit)
===============================

Binary artefacts are built by CI:

- [MacOS](https://circleci.com/gh/docker/vpnkit)
- [Windows](https://ci.appveyor.com/project/docker/vpnkit/history)

![VPNKit diagram](http://docker.github.io/vpnkit/vpnkit.png)

VPNKit is a set of tools and services for helping [HyperKit](https://github.com/docker/hyperkit)
VMs interoperate with host VPN configurations.

Building on Unix
----------------

First install `wget`, `opam` using your package manager of choice.
Install the OCaml library dependencies with:
```
make depends
```
Build the application using:
```
make
```

Running with hyperkit
---------------------

First ask `com.docker.slirp` to listen for ethernet connections on a local Unix domain socket:
```
com.docker.slirp --ethernet /tmp/ethernet --debug
```
Next ask [com.docker.hyperkit](https://github.com/docker/hyperkit) to connect a NIC to this
socket by adding a command-line option like `-s 2:0,virtio-vpnkit,path=/tmp/ethernet`. Note:
you may need to change the slot `2:0` to a free slot in your VM configuration.

Why is this needed?
-------------------

Running a VM usually involves modifying the network configuration on the host, for example
by activating Ethernet bridges, new routing table entries, DNS and firewall/NAT configurations.
Activating a VPN involves modifying the same routing tables, DNS and firewall/NAT configurations
and therefore there can be a clash -- this often results in the network connection to the VM
being disconnected.

VPNKit, part of [HyperKit](https://github.com/docker/hyperkit)
attempts to work nicely with VPN software by intercepting the VM traffic at the Ethernet level,
parsing and understanding protocols like NTP, DNS, UDP, TCP and doing the "right thing" with
respect to the host's VPN configuration.

VPNKit operates by reconstructing Ethernet traffic from the VM and translating it into the
relevant socket API calls on OSX or Windows. This allows the host application to generate
traffic without requiring low-level Ethernet bridging support.

Design
------

- [ethernet](docs/ethernet.md): describes the flow of ethernet traffic to/from the VM
- [DNS](docs/DNS.md): describes the DNS forwarder implementation

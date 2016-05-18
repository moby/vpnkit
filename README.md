VPN-friendly networking devices for [hyperkit](https://github.com/docker/hyperkit)
===============================

![VPNkit diagram](http://docker.github.io/vpnkit/vpnkit.png)

VPNkit is a set of tools and services for helping [hyperkit](https://github.com/docker/hyperkit)
VMs interoperate with host VPN configurations.

Why is this needed?
-------------------

Running a VM usually involves modifying the network configuration on the host, for example
by activating ethernet bridges, new routing table entries, DNS and firewall/NAT configurations.
Activating a VPN involves modifying the same routing tables, DNS and firewall/NAT configurations
and therefore there can be a clash-- this often results in the network connection to the VM
being disconnected.

VPNkit, part of [hyperkit](https://github.com/docker/hyperkit)
attempts to work nicely with VPN software by intercepting the VM traffic at the ethernet level,
parsing and understanding protocols like NTP, DNS, UDP, TCP and doing the "right thing" with
respect to the host's VPN configuration.


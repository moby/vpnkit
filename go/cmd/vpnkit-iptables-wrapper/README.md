#### VPNKit iptables wrapper for dockerd

This is an iptables wrapper that will call `vpnkit-expose-port` when a swarm port is published by `dockerd` inside the guest VM. The wrapper has to be installed as `iptables` in $PATH in a location that comes before the regular iptables. It expects regular iptables to exist in `/sbin/iptables`.

If the file `/var/config/vpnkit/native-port-forwarding` exists and contains a `0` all requests will be passed directly to `/sbin/iptables`, disabling the wrapper.


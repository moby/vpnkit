# Port-forwarding

This page describes how `vpnkit` is used by Docker for Mac and Docker for Windows to
open ports on host interfaces and to forward traffic to containers.

Note: this is completely separate from [using vpnkit as a default gateway](ethernet.md).
This implementation could be factored out into a separate executable.

## Background

On a regular installation of `docker` on Linux the command:

```
docker run -p 8080:80 nginx
```
starts an `nginx` container and forwards connections from `0.0.0.0:8080` on
the host to the container's port `80`.

The command:

```
docker run -p 1.2.3.4:8080:80 nginx
```
starts an `nginx` container but only forwards connections from `1.2.3.4:8080` on
the host to the container's port `80`.

On Linux port forwarding can be achieved either through `iptables` or by
running a simple user-space proxy. On Docker for Mac and Docker for Windows

- the `docker` daemon does not run on the host (except on Windows when running
  Windows containers-- this is out of scope of this document) and so cannot run
  anything on the host
- the container network within the VM is separated from the host's network
  by `vpnkit` (ignoring the internal network used on Windows for volume sharing):
  see [using vpnkit as default gateway](ethernet.md).

Therefore `vpnkit` includes a port forwarding service which allows the `docker` daemon
in the VM to open ports on the host and which forwards connections transparently
to the container port inside the VM.

## Docker daemon interface

The `docker` daemon can either use `iptables` or a userspace proxy to open ports
on a regular Linux system. In Docker for Mac and Docker for Windows we configure
the `docker` daemon to use a userspace proxy, and we provide our own custom
implementation. This acts as a very basic "plugin".

For example, after running `docker run -p 8080:80 nginx` on the host, inside the
VM we can see a process:

```
/usr/bin/slirp-proxy -proto tcp -host-ip 0.0.0.0 -host-port 8080 -container-ip 172.17.0.2 -container-port 80
```
This shows a single port forward from `0.0.0.0:8080` on the host to the internal
IP `172.17.0.2:80` inside the VM.

This custom proxy uses a custom signaling protocol to communicate the port forwarding
request to the host, and to receive back success or error (e.g. `EADDRINUSE`
or `EADDRNOTAVAIL`).

## Signalling from the VM to the host

The control interface takes the form of a virtual 9P filesystem served by
`vpnkit` and mounted in the Linux VM. New port forwards are requested by
creating directories, and status (including error messages) read by reading
files.

For example, after running `docker run -p 8080:80 nginx` on the host, inside
the VM we can see:
```
/ # ls /port
README                              tcp:0.0.0.0:8080:tcp:172.17.0.2:80
```
This shows a single active port forward from `0.0.0.0:8080` on the host to the internal
IP `172.17.0.2:80` inside the VM.

The initial filesystem mount is slightly different between Docker for Mac
and Docker for Windows.

The [hyperkit](https://github.com/moby/hyperkit) hypervisor on the Mac has a
[virtio-9p](https://github.com/moby/hyperkit/blob/master/src/lib/pci_virtio_9p.c)
device which connects to a Unix domain socket whenever the VM issues a `mount`
command.

On Windows we run a process `9p-mount` which calls `listen` on a Hyper-V socket for
connections from the host. `vpnkit` calls `connect`, and then `9p-mount` calls
`accept` and then passes
the file descriptor to the `mount` command via the `rfdno` and `wfdno`
arguments.

When it has opened a new host port forward, the custom proxy retains an open
file descriptor referencing a control file on the filesystem. If the proxy
is killed or crashes the Linux kernel will close the file descriptor and emit
a 9P `clunk` message which is used by `vpnkit` to shut down the port forward.
This ensures that the port forwards in `vpnkit` do not leak.

Note: the use of a mounted filesystem is not ideal, for if the `vpnkit` process
is restarted then the filesystem becomes broken. It would be better in future
to use a reconnectable protocol.

Note: the use of `clunk` like this is quite fragile; if another process were
to `open` and `close` the file it would prematurly call `clunk` and shutdown
the port forward.

## Forwarding connections

When a client connects to the port on the host, `vpnkit` accepts the connection.

On Windows, `vpnkit` calls `connect` on a Hyper-V socket to connect to the VM
on a well-known port.

On the Mac, `vpnkit` calls `connect` on a Unix domain socket to connect to the
[hyperkit](https://github.com/moby/hyperkit) hypervisor's `virtio-vsock` control
socket. `vpnkit` writes a short header including the well-known `AF_VSOCK`
port number and is connected to the VM.

Inside
the VM there is a connection demultiplexer which calls `listen` on this well-known port.
This process calls `accept` and then reads a simple header which includes the
ultimate destination IP and port (`172.17.0.2:80` in the example above).
The demultiplexer calls `connect` to the container port and starts proxying data.

Note: since early versions of Windows 10 do not support `shutdown` (i.e. the
ability to signal that `write` calls have finished but while allowing `read` calls to continue
c.f. TCP half-close) there is a simple protocol layered over the Hyper-V socket
stream which implements this behaviour, not described here.

Note: the code also transports UDP with a simple framing protocol, not described here.

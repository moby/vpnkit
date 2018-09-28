# Port forwarding protocol

The control-plane interface is over 9P and not described here. This document
describes the data-plane only.

The `vpnkit` process connects to `vpnkit-forwarder` over hypervisor sockets
and exchanges a series of framed messages in both directions. Each message
contains a `command` and an `ID`. The protocol supports multiplexing logical
connections over one physical connection, where the `ID` identifies the logical
connection.

The first message is sent from `vpnkit` to `vpnkit-forwarder` with fields

| Offset        | Field         | Value                     |
| ------------- |---------------|---------------------------|
| 0             | `hdrlen`      | `uint16` length of header |
| 2             | `command`     | `uint8(1)` (Open)         |
| 3             | `ID`          | `uint32(id)`              |
| 7             | `connection`  | `uint8(2)` (Multiplexed)  |
| 8             | `proto`       | `uint8(1)` (TCP)          |
| 9             | `iplen`       | `uint16(4 or 16)`         |
| 11            | `ip`          | 4 or 16 bytes (IP)        |
| 11 + `iplen`  | `port`        | `uint16(port)` (port)     |

This requests a TCP connection be opened and associated with `id`, using the
Multiplexed protocol. If the `connection` was set to `Dedicated` then the
hypervisor socket connection would be proxied directly to the remote IP.

At this point either end can send messages the following messages referencing
this `id`:
- `command` = `close` (2): requests the connection is closed. The other end
  should send the same message back to confirm the closure and free the `id`
- `command` = `shutdown` (3): signals that no more data will be written in
  this direction and EOF can be sent to the application.

The remaining messages are:

To send a TCP payload:

| Offset        | Field         | Value                     |
| ------------- |---------------|---------------------------|
| 0             | `hdrlen`      | `uint16` length of header |
| 2             | `command`     | `uint8(4)` (Data)         |
| 3             | `ID`          | `uint32(id)`              |
| 7             | `payloadlen`  | `uint32(len)`             |

To open up the send window:

| Offset        | Field         | Value                     |
| ------------- |---------------|---------------------------|
| 0             | `hdrlen`      | `uint16` length of header |
| 2             | `command`     | `uint8(5)` (Window)       |
| 3             | `ID`          | `uint32(id)`              |
| 7             | `payloadlen`  | `uint64(seq)`             |

To send a UDP datagram:

| Offset        | Field         | Value                     |
| ------------- |---------------|---------------------------|
| 0             | `hdrlen`      | `uint16` length of header |
| 2             | `command`     | `uint8(6)` (UDP)          |
| 3             | `ID`          | `uint32(id)`              |
| 7             | `iplen`       | `uint16(4 or 16)`         |
| 9             | `ip`          | 4 or 16 bytes (IP)        |
| 9 + `iplen`   | `port`        | `uint16(port)` (port)     |
| 11 + `iplen`   | `seq`         | `uint64(seq)`            |

If the `vpnkit-forwarder` receives UDP which it can't transmit due to lack
of buffer space, the packet can be dropped. TCP payloads cannot be dropped
so we must use flow control to prevent more data being sent than the
receiver can handle. When a TCP connection is Open, the send window is set
to 0 in both directions. Both sides exchange `Window` messages to permit
the transmission of data up to a sequence number. Both sides know how much
buffer space they will allocate to each connection, and will send new `Window`
messages before the buffer space is completely exhausted.
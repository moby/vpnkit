# DNS

We wish to support the following features

- the host DNS settings can change without having to reconfigure the client
  (e.g. this covers the case of changing wifi networks)
- arbitrary numbers of upstream DNS servers
- sending DNS queries to subsets of upstream DNS servers depending on the
  domain (e.g. `*.corp` sent only to internal VPN server, everything else to
  `8.8.8.8`)
- extra records from other sources e.g. `/etc/hosts`
  (or maybe `this.host.docker.com`?)
- search domains (e.g. `*.corp`)
- debugability: capture last `n` queries in a ring buffer and include them in
  a diagnostics dump

As of 2016-09-28, we have a TCP and UDP-level message forwarder, where a flat
list of virtual IPs is provided to the VM and these are mapped onto upstream
servers. Unfortunately this has limitations including

- resolver implementations often use only a subset of the upstream servers
- Linux resolvers don't have the concept of "zones" so they often pick
  the wrong subset of servers to try

We will extend the message forwarder to be a full DNS proxy which can take
zone information into account.

## Design

### Request pipeline

All DNS packets are appended to the debug packet ring (stored in memory).

- request is received on the single virtual IP configured by DHCP
- request is matched against "extra records" such as those from `/etc/hosts`
- upstream servers are selected based on the domain name
- requests are sent to all upstream servers
- first response is returned (which might be a "domain does not exist" if the
  wrong servers are selected)

### Server selection

If the request matches the domain of any upstream servers (in cases where the
upstream servers have associated domains like `*.corp`) then the request will be
sent *only* to matching servers. This avoids sending requests for internal VPN
domains to public Internet DNS servers and receiving "domain does not exist"
errors.

If the request does not match the domain of any upstream servers (the common case)
then all servers are selected. We don't want to send a request to only one,
because if it times out then the client will submit another request which is
difficult to reliably associate with the first, causing us to select the same
broken server again.

### Connection handling

We must

- be prepared to resend requests over TCP if the response is too big to fit into
  a UDP datagram
- be able to multiplex requests and responses across a single TCP connection
- cope with servers which don't actually support TCP (even though they should)
- avoid leaving sockets open for long periods of time (since they are a limited
  resource on the Mac)

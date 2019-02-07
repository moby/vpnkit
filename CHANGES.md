### v0.3.0 (2019-02-06)

* support multiplexing forwarded connections along one Hyper-V socket connection
* add Kubernetes controller for exposing ports
* go: move to go dep
* support building Linux static binaries (with musl)
* add a --gateway-forwards file for redirecting traffic to external services
* udp: prevent too many flows exhausting all fds on the system
* support forwarding to Unix domain sockets as well as TCP and UDP
* go: move vmnet to its own package
* test: add an nmap simulation test
* vpnkit-{9pmount,tap}-vsock: fix operation on newer kernels with AF\_VSOCK
* rename environment varible from DEBUG to VPNKIT\_DEBUG to avoid clashing with
  other software
* tcp: disable keep-alives: they were causing a space leak
* http: HTTP/1.0 should default to Connection:close
* icmp: don't log parse failures
* ntp: remove the automatic NTP forward to localhost: use the --gateway-forwards
  feature instead
* http: handle Connection:close
* http: consult the "localhost" names in the transparent proxy
* http: support both hostnames and IPs in excludes
* http: fix HTTP CONNECT
* http: respect authorization headers
* http: HEAD responses must not have bodies

### v0.2.0 (2018-01-03)

* add 9pmount-vsock and tap-vsock helper programs
* add missing command-line options and support running without the database
* add go library and helper tools to expose ports
* tcp: enable keep-alives
* tcp: disable nagle
* udp: drop packets with incorrect source addresses
* test: record one .pcap trace per test
* icmp: add support for ping
* dns: use persistent TCP connections but transient UDP "connections" to increase
  the request entropy
* dns: increase scalability on the Mac
* http: add a regular HTTP proxy (as well as the transparent one)
* windows: use `RtlGenRandom` for entropy
* windows: be more robust to Hyper-V socket failures
* fix build with `-safe-string` and OCaml 4.06
* support builds with the system OCaml compiler
* socket protocol updated to v22:
    - support error messages returned to client for Ethernet and Preferred_ipv4
      slirp commands
    - allow client to request an IPv4 address without encoding it in the UUID
    - v1 no longer supported, clients have to be updated. Version 22 is used to
      match the current version number in Docker for Desktop.

### v0.1.1 (2017-08-17)

* simplify the build by watermarking with `jbuilder subst`
* fix the build of the released package archive

### v0.1.0 (2017-08-17)

* use Mirage 3 interfaces
* add support for ICMP ECHO_REQUESTS
* add support for transparent HTTP/HTTPS proxying


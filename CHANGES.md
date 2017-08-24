### unreleased

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


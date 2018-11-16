
This repository contains Go bindings and sample code for [Hyper-V sockets](https://msdn.microsoft.com/en-us/virtualization/hyperv_on_windows/develop/make_mgmt_service) and [virtio sockets](http://stefanha.github.io/virtio/)(VSOCK).

## Organisation

- `pkg/hvsock`: Go binding for Hyper-V sockets
- `pkg/vsock`: Go binding for virtio VSOCK
- `cmd/sock_stress`: A stress test program for virtsock
- `cmd/vsudd`: A unix domain socket to virtsock proxy (used in Docker for Mac/Windows)
- `scripts`: Miscellaneous scripts
- `c`: Sample C code (including benchmarks and stress tests)
- `data`: Data from benchmarks


## Building

By default the Go sample code is build in a container. Simply type `make`.

If you want to build binaries on a local system use `make build-binaries`.

## Testing

There are several examples and tests written both in [Go](./cmd) and in [C](./c). The C code is Hyper-V sockets specific while the Go code also works with virtio sockets and [HyperKit](https://github.com/moby/hyperkit). The respective READMEs contain instructions on how to run the tests, but the simplest way is to use [LinuxKit](https://github.com/linuxkit/linuxkit).

Assuming you have LinuxKit installed, the make target `make linuxkit`
will build a custom Linux image which can be booted on HyperKit or on
Windows. The custom Linux image contains the test binaries.

### macOS

Boot the Linux VM:
```
linuxkit run hvtest
```
This should create a directory called `./hvtest-state`.

Run the server in the VM and client on the host:
```
linux$ sock_stress -s vsock -v 1
macos$ ./bin/sock_stress.darwin -c vsock://3 -m hyperkit:./hvtest-state -v 1
```

Run the server on the host and the client inside the VM:
```
macos$ ./bin/sock_stress.darwin -s vsock -m hyperkit:./hvtest-state -v 1
linux$ sock_stress -c vsock://2 -v 1
```

### Windows

TBD

## Known limitations

- `hvsock`: The Windows side does not implement `accept()` due to
  limitations on some Windows builds where a VM can not connect to the
  host via Hyper-V sockets.

- `vsock`: There is general host side implementation as the interface
  is hypervisor specific. The `vsock` package includes some support
  for connecting with the VSOCK implementation in
  [Hyperkit](https://github.com/moby/hyperkit), but there is no
  implementation for, e.g. `qemu`.


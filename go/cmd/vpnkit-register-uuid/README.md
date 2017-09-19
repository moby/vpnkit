# vpnkit-register-uuid

`vpnkit` associates ethernet clients with UUIDs. When a client reconnects, it provides
the same UUID as it used in the past and then it will be allocated the same MAC
and DHCP IP address.

`vpnkit-register-uuid` calls vpnkit to register a given UUID and returns the IP address.
This allows the following sequence:

1. read a UUID from a config file (or generate a fresh one)
2. use `vpnkit-register-uuid` to register the UUID and discover the IP
3. start a VM with [hyperkit](https://github.com/moby/hyperkit) with a VIF using this UUID
4. connect to a service running in the VM using the IP

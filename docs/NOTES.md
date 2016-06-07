Implementation Notes
--------------------

On Windows we depend on Hyper-V sockets (`AF_HYPERV`). There are two services
with the following GUIDs:

- ethernet: `30D48B34-7D27-4B0B-AAAF-BBBED334DD59`
- port forwarding: `0B95756A-9985-48AD-9470-78E060895BE7`

These services must be registered in the registry, see the powershell script
[register.ps1](https://github.com/docker/vpnkit/blob/master/src/com.docker.slirp.exe/register.ps1).

To start the service, first discover the VM Id with:

```powershell
(Get-VM -Name myvmname).Id
```

and then:
```bash
./com.docker.slirp.exe --ethernet hyperv-connect://<VM UUID> --debug
```

Since Hyper-V sockets don't currently support graceful shutdown, the port
forwarding code uses a simple message-based protocol where messages can
be

- data
- a shutdown read request
- a shutdown write request
- a close request

Once a peer has received an acknowledgement of a close request it is free
to actually close the socket (which will discard any remaining in-flight
data).

See
https://github.com/rneugeba/virtsock/tree/master/go/hvsock

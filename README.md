Networking devices for [hyperkit](https://github.com/docker/hyperkit)
===============================

Notes
-----

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

# Transparent HTTP(S) proxying

Some networks require all HTTP(S) requests to be sent via official proxies
and block direct outgoing connections on port 80 and port 443.
One way to respect this policy is to reconfigure all software to use the official
proxies, for example through setting the `http_proxy` environment variables.

However this has some disadvantages including

- the specific proxies in use can end up baked-in to software images, making
  them non-portable.
- communication between containers (or VMs or other entities) behind the proxy
  over HTTP(S) will be bounced via the proxy unless the `no_proxy` environment
  is set correctly.
- changing the proxy setting requires restarting the programs because it is not
  possible to change environment variables on-the-fly.
- not all software respects the `http_proxy` environment variable anyway.

We can work around all these disadvantages by using the new
experimental transparent HTTP(S)
proxy inside `vpnkit`. The proxy will capture all outgoing traffic on port 80
and port 443 and redirect it to the appropriate upstream proxy. None of the
client software needs to know the current proxy settings or needs to monitor it
for changes.

## Enabling the proxy in recent Docker for Mac builds

The *master* branch of Docker for Mac https://download-stage.docker.com/mac/master/Docker.dmg
contains the latest version of `vpnkit` and can be used to experiment with the
transparent HTTP proxy. Note this build of Docker for Mac is not suitable for
production use.

After installing Docker for Mac, open a terminal and type:
```
cd ~/Library/Containers/com.docker.docker/Data/database/
git reset --hard
mkdir -p com.docker.driver.amd64-linux/slirp
echo -n true > com.docker.driver.amd64-linux/slirp/enable-http-intercept
git add com.docker.driver.amd64-linux/slirp/enable-http-intercept
git commit -s -m 'Enable HTTP interception'
```
Next, restart Docker for Mac.

If the Docker Preferences (whale menu -> Preferences -> Proxies) are configured
to "Use system proxy" then the settings will be taken directly from the MacOS
System Preferences -> Network -> Advanced -> Proxies settings.

## Disabling the proxy again

To disable the proxy, open a terminal and type:
```
cd ~/Library/Containers/com.docker.docker/Data/database/
git reset --hard
git rm com.docker.driver.amd64-linux/slirp/enable-http-intercept
git commit -s -m 'Disable HTTP interception'
```

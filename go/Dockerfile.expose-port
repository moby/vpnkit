FROM linuxkit/alpine:3683c9a66cd4da40bd7d6c7da599b2dcd738b559 AS mirror

RUN apk add --no-cache go musl-dev

ENV GOPATH=/go PATH=$PATH:/go/bin

COPY . /go/src/github.com/moby/vpnkit/go
RUN go-compile.sh /go/src/github.com/moby/vpnkit/go/cmd/vpnkit-expose-port
RUN go-compile.sh /go/src/github.com/moby/vpnkit/go/cmd/vpnkit-iptables-wrapper

FROM scratch
ENTRYPOINT []
CMD []
WORKDIR /
COPY --from=mirror /go/bin/vpnkit-expose-port /usr/bin/vpnkit-expose-port
COPY --from=mirror /go/bin/vpnkit-iptables-wrapper /usr/bin/vpnkit-iptables-wrapper

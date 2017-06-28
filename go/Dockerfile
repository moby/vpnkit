FROM linuxkit/alpine:630ee558e4869672fae230c78364e367b8ea67a9 AS mirror

RUN apk add --no-cache go musl-dev build-base

ADD . /go/src/github.com/moby/vpnkit/go
WORKDIR /go/src/github.com/moby/vpnkit/go

RUN GOPATH=/go make build/vpnkit-forwarder.linux

FROM scratch
COPY --from=mirror /go/src/github.com/moby/vpnkit/go/build/vpnkit-forwarder.linux /vpnkit-forwarder
CMD ["/vpnkit-forwarder"]



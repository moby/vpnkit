# syntax=docker/dockerfile:1
FROM linuxkit/alpine:316c3f9d85c21fdd8bc7479e81d290f85bf60eb0 AS mirror

RUN apk add --no-cache go musl-dev build-base

ENV GOPATH=/go
COPY . /go/src/github.com/moby/vpnkit
RUN go-compile.sh /go/src/github.com/moby/vpnkit/go/cmd/vpnkit-forwarder

FROM scratch
COPY --link --from=mirror /go/bin/vpnkit-forwarder /usr/bin/vpnkit-forwarder
CMD ["/usr/bin/vpnkit-forwarder"]

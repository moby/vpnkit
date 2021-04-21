FROM linuxkit/alpine:77f48acc94bdda04e7be1e501a234c2b5c0d6593 AS mirror

RUN apk add --no-cache go musl-dev build-base

ENV GOPATH=/go
COPY . /go/src/github.com/moby/vpnkit
RUN go-compile.sh /go/src/github.com/moby/vpnkit/go/cmd/vpnkit-forwarder

FROM scratch
COPY --from=mirror /go/bin/vpnkit-forwarder /usr/bin/vpnkit-forwarder
CMD ["/usr/bin/vpnkit-forwarder"]



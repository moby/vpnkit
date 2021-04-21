FROM linuxkit/alpine:77f48acc94bdda04e7be1e501a234c2b5c0d6593 AS mirror

RUN apk add --no-cache go musl-dev build-base

ENV GOPATH=/go
ADD . /go/src/github.com/moby/vpnkit/go
WORKDIR /go/src/github.com/moby/vpnkit/go

RUN make test
RUN make build/vpnkit-forwarder.linux

FROM scratch
COPY --from=mirror /go/src/github.com/moby/vpnkit/go/build/vpnkit-forwarder.linux /vpnkit-forwarder
CMD ["/vpnkit-forwarder"]



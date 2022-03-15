FROM linuxkit/alpine:2be490394653b7967c250e86fd42cef88de428ba AS mirror

RUN apk add --no-cache go musl-dev build-base

ENV GOPATH=/go
COPY . /go/src/github.com/moby/vpnkit
RUN go-compile.sh /go/src/github.com/moby/vpnkit/go/cmd/vpnkit-forwarder

FROM scratch
COPY --from=mirror /go/bin/vpnkit-forwarder /usr/bin/vpnkit-forwarder
CMD ["/usr/bin/vpnkit-forwarder"]



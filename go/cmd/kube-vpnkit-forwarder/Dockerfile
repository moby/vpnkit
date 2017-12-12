FROM linuxkit/alpine:3fb44354a34b05134fbf585a00217cd2f8c8f0bf AS build
RUN apk add --no-cache go musl-dev git build-base
ENV GOPATH=/go PATH=$PATH:/go/bin
COPY . /go/src/kube-vpnkit-forwarder
RUN go-compile.sh /go/src/kube-vpnkit-forwarder

FROM scratch
WORKDIR /
ENTRYPOINT ["/usr/bin/kube-vpnkit-forwarder"]
COPY --from=build /go/bin/kube-vpnkit-forwarder /usr/bin/kube-vpnkit-forwarder

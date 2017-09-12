FROM alpine:3.6 as build
RUN apk add --no-cache go musl-dev build-base linux-headers

COPY . /build
RUN make -C /build sbin/vpnkit-9pmount-vsock

FROM scratch
ENTRYPOINT []
CMD []
WORKDIR /
COPY --from=build /build/sbin/vpnkit-9pmount-vsock /sbin/vpnkit-9pmount-vsock

FROM alpine:3.8 as build
RUN apk add --no-cache musl-dev build-base linux-headers

COPY . /build
RUN make -C /build sbin/vpnkit-9pmount-vsock

# Can't use scratch as we need /bin/mount
FROM alpine:3.8
ENTRYPOINT []
CMD []
WORKDIR /
COPY --from=build /build/sbin/vpnkit-9pmount-vsock /sbin/vpnkit-9pmount-vsock

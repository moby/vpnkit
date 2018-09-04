FROM alpine:3.8 as build
RUN apk add --no-cache musl-dev build-base linux-headers

COPY . /build
RUN make -C /build sbin/vpnkit-tap-vsockd

# Using alpine rather than scratch allows us to support post-up scripts
FROM alpine:3.8

COPY --from=build /build/sbin/vpnkit-tap-vsockd /sbin/vpnkit-tap-vsockd
CMD [ "/sbin/vpnkit-tap-vsockd", "--tap", "eth0", "--message-size", "8192", "--buffer-size", "262144", "--listen" ]

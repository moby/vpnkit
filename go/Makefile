.PHONY: all clean fmt lint

ORG?=vpnkit
IMAGE=vpnkit-forwarder
DEPS_FORWARDER:=$(wildcard cmd/vpnkit-forwarder/*.go)
DEPS_DIAL_EXAMPLE:=$(wildcard cmd/dial-example/*.go)
DEPS_IPTABLES:=$(wildcard cmd/vpnkit-iptables-wrapper/*.go)
DEPS_KUBE_FORWARDER:=$(wildcard cmd/kube-vpnkit-forwarder/*.go)
DEPS:=$(DEPS_IPTABLES) $(DEPS_FORWARDER)
HASH?=$(shell git ls-tree HEAD -- ../$(notdir $(CURDIR)) | awk '{print $$3}')

# This may fail when cross compiling as virtsock requires cgo
all: build/vpnkit-iptables-wrapper.linux build/vpnkit-forwarder.linux build/vpnkit-expose-port.linux build/kube-vpnkit-forwarder.linux build/dial-example.linux

# Test
test:
	go test -race -v ./cmd/... ./pkg/...

build-push:
	docker buildx build --push --platform linux/amd64,linux/arm64 -t $(ORG)/vpnkit-forwarder:$(HASH) -f Dockerfile ..

# Build in linux container
build-in-container: build-forwarder-in-container build-expose-port-in-container build-kube-forwarder-in-container build-dial-example-in-container

build-forwarder-in-container: $(DEPS_FORWARDER)
	docker build -t $(ORG)/vpnkit-forwarder:$(HASH) -f Dockerfile ..

build-expose-port-in-container: $(DEPS)
	docker build -t $(ORG)/vpnkit-expose-port:$(HASH) -f Dockerfile.expose-port ..

build-kube-forwarder-in-container: $(DEPS_KUBE_FORWARDER)
	docker build -t $(ORG)/kube-vpnkit-forwarder:$(HASH) -f Dockerfile.kube-forwarder ..

build-dial-example-in-container: $(DEPS_DIAL_EXAMPLE)
	docker build -t $(ORG)/dial-example:$(HASH) -f Dockerfile.dial-example ..

build/vpnkit-forwarder.linux: $(DEPS_FORWARDER)
	GOOS=linux \
	go build -o $@ --ldflags '-s -w -extldflags "-static"' --buildmode pie \
	$(DEPS_FORWARDER)

build/vpnkit-expose-port.linux: build/vpnkit-forwarder.linux
	cp -v build/vpnkit-forwarder.linux build/vpnkit-expose-port.linux

build/dial-example.linux: $(DEPS_DIAL_EXAMPLE)
	GOOS=linux CGO_ENABLED=1 \
	go build -o $@ --ldflags '-s -w' --buildmode pie \
	$(DEPS_DIAL_EXAMPLE)

build/kube-vpnkit-forwarder.linux: $(DEPS_KUBE_FORWARDER)
	GOOS=linux CGO_ENABLED=1 \
	go build -o $@ --ldflags '-s -w' --buildmode pie \
	$(DEPS_KUBE_FORWARDER)

build/vpnkit-iptables-wrapper.linux: $(DEPS_IPTABLES)
	GOOS=linux CGO_ENABLED=0 \
	go build -o $@ --ldflags '-s -w' --buildmode pie \
	$(DEPS_IPTABLES)

clean:
	rm -rf build

fmt:
	gofmt -s -l . 2>&1 | grep -v ^vendor/ | xargs gofmt -s -l -w

lint:
	$(if $(shell which golint || echo ''), , \
		$(error Please install golint))
	test -z "$$(golint ./... 2>&1 | grep -v ^vendor/ | grep -v mock/ | tee /dev/stderr)"

.DELETE_ON_ERROR:

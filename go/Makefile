.PHONY: all clean fmt lint

ORG?=vpnkit
IMAGE=vpnkit-forwarder
DEPS:=$(wildcard cmd/vpnkit-forwarder/*.go)
HASH?=$(shell git ls-tree HEAD -- ../$(notdir $(CURDIR)) | awk '{print $$3}')

# This may fail when cross compiling as virtsock requires cgo
all: build/vpnkit-forwarder.linux build/vpnkit-expost-port.linux

# Build in linux container
build-in-container: build-forwarder-in-container build-expose-port-in-container

build-forwarder-in-container: $(DEPS)
	docker build -t $(ORG)/vpnkit-forwarder:$(HASH) -f Dockerfile .

build-expose-port-in-container: $(DEPS)
	docker build -t $(ORG)/vpnkit-expose-port:$(HASH) -f Dockerfile.expose-port .

build/vpnkit-forwarder.linux: $(DEPS)
	GOOS=linux GOARCH=amd64 \
	go build -o $@ --ldflags '-s -w -extldflags "-static"' --buildmode pie \
	$(DEPS)

build/vpnkit-expose-port.linux: build/vpnkit-forwarder.linux
	cp -v build/vpnkit-forwarder.linux build/vpnkit-expose-port.linux

clean:
	rm -rf build

fmt:
	gofmt -s -l . 2>&1 | grep -v ^vendor/ | xargs gofmt -s -l -w

lint:
	$(if $(shell which golint || echo ''), , \
		$(error Please install golint))
	test -z "$$(golint ./... 2>&1 | grep -v ^vendor/ | grep -v mock/ | tee /dev/stderr)"

.DELETE_ON_ERROR:

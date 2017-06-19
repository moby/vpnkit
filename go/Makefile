.PHONY: all clean fmt lint

ORG?=vpnkit
IMAGE=vpnkit-forwarder
DEPS:=$(wildcard cmd/vpnkit-forwarder/*.go)
HASH?=$(shell git ls-tree HEAD -- ../$(notdir $(CURDIR)) | awk '{print $$3}')

build-in-container: $(DEPS)
	docker build -t vpnkit-forwarder-build -f ./Dockerfile.build .
	docker run --rm \
		-v ${CURDIR}/build:/go/src/github.com/moby/vpnkit/go/build \
		vpnkit-forwarder-build

from-scratch: build-in-container
	docker build -t $(ORG)/$(IMAGE):$(HASH) -f ./Dockerfile.scratch .

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

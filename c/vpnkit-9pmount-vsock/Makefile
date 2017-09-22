.PHONY: all clean build-in-container

DEPS=$(wildcard *.c *.h)
HASH?=$(shell git ls-tree HEAD -- ../$(notdir $(CURDIR)) | awk '{print $$3}')

all: sbin/vpnkit-9pmount-vsock

build-in-container:
	docker build -t vpnkit-9pmount-vsock:$(HASH) -f Dockerfile .

sbin/vpnkit-9pmount-vsock: $(DEPS)
	mkdir -p sbin
	gcc -static -o "$@" -O2 -Wall -Werror $^

clean:
	rm -rf sbin

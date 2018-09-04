.PHONY: all clean build-in-container

SRC=$(wildcard *.c)
HASH?=$(shell git ls-tree HEAD -- ../$(notdir $(CURDIR)) | awk '{print $$3}')

all: sbin/vpnkit-tap-vsockd

build-in-container:
	docker build -t vpnkit-tap-vsockd:$(HASH) -f Dockerfile .

sbin/vpnkit-tap-vsockd: $(SRC)
	mkdir -p sbin
	gcc -static -o "$@" -lpthread -O2 -Wall -Werror $^

clean:
	rm -rf sbin

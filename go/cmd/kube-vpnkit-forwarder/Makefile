ORG?=linuxkitprojects
IMAGE=kube-vpnkit-forwarder
HASH?=$(shell git ls-tree HEAD -- ../$(notdir $(CURDIR)) | awk '{print $$3}')

.PHONY: build
build:
	docker build -t $(ORG)/$(IMAGE):$(HASH) .

.PHONY: run
run: build
	docker tag $(ORG)/$(IMAGE):$(HASH) $(ORG)/$(IMAGE):current
	-kubectl -n kube-system delete daemonset kube-vpnkit-forwarder
	kubectl apply -f kube-vpnkit-forwarder.yaml

default: build

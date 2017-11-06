ORG?=linuxkitprojects
IMAGE=kubernetes-vpnkit-expose-port-controller
HASH?=$(shell git ls-tree HEAD -- ../$(notdir $(CURDIR)) | awk '{print $$3}')

.PHONY: build
build:
	docker build -t $(ORG)/$(IMAGE):$(HASH) .

.PHONY: run
run: build
	docker tag $(ORG)/$(IMAGE):$(HASH) $(ORG)/$(IMAGE):current
	-kubectl -n kube-system delete daemonset vpnkit-expose-port-controller
	kubectl apply -f vpnkit-expose-port-controller.yaml

default: build

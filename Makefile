IMAGE_PLATFORMS ?= linux/amd64,linux/arm64
IMAGE_NAME ?= skbdump
IMAGE_NAME_DEV ?= skbdump-dev

DOCKER_BUILD_DEV := docker build -f hack/Dockerfile --target dev --tag $(IMAGE_NAME_DEV) .

DELVE_PORT_FORWARD := $(if $(DELVE_PORT),-p "127.0.0.1:$(DELVE_PORT):$(DELVE_PORT)",)
DOCKER_RUN := docker run --rm -it \
	--privileged $(DELVE_PORT_FORWARD) \
	--cgroupns host \
	-v ./:/skbdump \
	-w /skbdump \
	-e DELVE_PORT \
	-e SKBDUMP_DEBUG \
	$(IMAGE_NAME_DEV)

KERNEL_VERSION ?= 6.9.2
BUSYBOX_VERSION ?= 1_36_0

.PHONY: dev
# Start a dev container
dev:
	$(DOCKER_BUILD_DEV)
	$(DOCKER_RUN) /bin/bash

.PHONY: generate
# Generate BPF objects
generate:
ifeq ($(WITH_DOCKER),1)
	docker run --rm -v ./:/skbdump -w /skbdump golang:1.23 /bin/sh -c '\
		apt-get update && \
		apt-get install -y clang && \
		go generate ./bpf'
else
	go generate ./bpf
endif

.PHONY: release
# Build and push Docker image
release:
ifeq ($(IMAGE_TAG),)
	@echo "ERROR: IMAGE_TAG not set."
	@exit 1
endif
	docker build --platform $(IMAGE_PLATFORMS) --tag $(IMAGE_NAME):$(IMAGE_TAG) .
	docker push $(IMAGE_NAME):$(IMAGE_TAG)

.PHONY: validate
validate:
	$(DOCKER_BUILD_DEV)
	$(DOCKER_RUN) ./hack/validate.sh

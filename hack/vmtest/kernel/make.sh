#!/bin/bash

[[ "${DEBUG:-}" != "" ]] && set -o xtrace

KERNEL_VERSION=${KERNEL_VERSION:-6.11.7}
TARGET=${TARGET:-sources}

docker build \
    --progress=plain \
    --target=${TARGET} \
    --build-arg=KERNEL_VERSION=${KERNEL_VERSION} \
    --tag kernel:${TARGET} \
    hack/vmtest/kernel

docker run --rm -it \
    -v ./hack/vmtest/kernel/config-${KERNEL_VERSION}:/build/.config \
    kernel:${TARGET} $@

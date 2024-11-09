#!/bin/bash

set -o xtrace


clang -O3 -Wall -Werror -DBPF_NO_GLOBAL_DATA -mcpu=v1 -g -target bpf \
    -D__TARGET_ARCH_arm64 \
    -I./bpf/headers \
    -I./bpf \
    -c ./bpf/tracer.c \
    -o ./pkg/skbdump/tracer.o

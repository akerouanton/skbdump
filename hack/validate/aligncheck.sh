#!/bin/bash

./hack/make/bpf.sh
go run -tags aligncheck ./tools/aligncheck $(pwd)/pkg/skbdump/tracer.o

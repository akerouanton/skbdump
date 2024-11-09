#!/bin/bash

./hack/validate/aligncheck.sh

# TODO(aker): Add more checks here.
go vet ./...
# go fmt ./...
# golangci-lint run

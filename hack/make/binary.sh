#!/bin/sh

set -o xtrace

if [ -n "${SKBDUMP_DEBUG}" ]; then
  GCFLAGS="all=-N -l"
fi

go build -gcflags="${GCFLAGS}" -o bin/skbdump ./cmd

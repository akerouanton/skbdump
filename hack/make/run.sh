#!/bin/bash

set -o xtrace

if [ "${SKBDUMP_DEBUG}" != "" ]; then
  if [ "${DELVE_PORT}" == "" ]; then
    echo "ERROR: DELVE_PORT is not specified."
    exit 1
  fi

  dlv \
    --listen=0.0.0.0:${DELVE_PORT} \
    --headless=true \
    --api-version=2 \
    --accept-multiclient \
    exec bin/skbdump -- "$@"
else
  bin/skbdump "$@"
fi

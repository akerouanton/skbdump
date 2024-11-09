#!/bin/bash

set -o nounset
set -o errexit
set -o pipefail

HACK_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

for arg in "$@"; do
    if [ ! -f ${HACK_DIR}/make/${arg}.sh ]; then
        echo "ERROR: script $arg not supported."
        exit 1
    fi

    ${HACK_DIR}/make/${arg}.sh
done

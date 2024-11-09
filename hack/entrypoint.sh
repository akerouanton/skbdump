#!/bin/sh

set -o xtrace

if [ "${AUTO_MOUNT}" != "" ]; then
  if ! $(grep debugfs /etc/mtab >/dev/null); then
    mount -t debugfs nodev /sys/kernel/debug
  fi

  if ! $(grep bpffs /etc/mtab >/dev/null); then
    mount -t bpf bpffs /sys/fs/bpf
  fi
fi

exec $@
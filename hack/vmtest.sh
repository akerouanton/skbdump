#!/bin/bash

set -o errexit

KERNEL_VERSION=${KERNEL_VERSION:-6.11.7}

while [ $# -ge 1 ]; do
    case "$1" in
        kernel)
            (
                set -x

                docker build \
                    --progress=plain \
                    --target=out-vmlinux \
                    --build-arg=KERNEL_VERSION=${KERNEL_VERSION} \
                    --output=type=local,dest=tests/vmtest/ \
                    hack/vmtest/kernel
            )
        ;;

        kernel-menuconfig)
            (
                set -x

                ./hack/vmtest/kernel/make.sh make menuconfig
            )
        ;;

        rootfs)
            (
                set -x

                docker build \
                    --progress=plain \
                    --target=out-rootfs \
                    --output=type=local,dest=tests/vmtest/rootfs \
                    --file=hack/vmtest/rootfs/Dockerfile \
                    hack/vmtest/rootfs
            )
        ;;

        *)
            set +o xtrace

            echo "ERROR: Unsupported command '$1'"
            echo ""

            echo "Usage: $0 kernel|kernel-menuconfig|rootfs"
            echo ""

            echo "Subcommands:"
            echo "    kernel:             Build the kernel"
            echo "    kernel-menuconfig:  Open Kernel's menuconfig"
            echo "    rootfs:             Build an uncompressed / unarchived rootfs"

            exit 1
        ;;
    esac

    shift
done

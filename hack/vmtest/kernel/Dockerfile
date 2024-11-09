FROM alpine AS build-tools

RUN apk add --no-cache \
    alpine-sdk \
    autoconf \
    bc \
    bison \
    flex \
    make \
    ncurses-dev \
    openssl-dev \
    xz \
    zstd

####################

FROM build-tools AS sources

ARG KERNEL_VERSION
ENV KERNEL_VERSION=${KERNEL_VERSION}

RUN mkdir /build /boot && \
    wget -O /build/linux-${KERNEL_VERSION}.tar.xz https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz && \
    tar -C /build -xvf /build/linux-${KERNEL_VERSION}.tar.xz

WORKDIR /build/linux-${KERNEL_VERSION}

COPY entrypoint /entrypoint
ENTRYPOINT ["/entrypoint"]
CMD ["/bin/sh", "-s"]

####################

FROM sources AS build

ARG KERNEL_VERSION

RUN --mount=type=bind,source=config-${KERNEL_VERSION},target=config \
    cp config .config && \
    make prepare && \
    make -j $(getconf _NPROCESSORS_ONLN) && \
    make -j $(getconf _NPROCESSORS_ONLN) headers && \
    find usr/include/ ! -iname "*.h" -type f -exec rm -v {} \+ && \
    make modules_install install

####################

FROM scratch AS out-vmlinux

ARG KERNEL_VERSION

COPY --from=build /boot/vmlinux-${KERNEL_VERSION} /vmlinux

####################

FROM scratch AS out-headers

ARG KERNEL_VERSION

COPY --from=build /build/linux-${KERNEL_VERSION}/usr/include/ /

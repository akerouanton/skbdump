FROM alpine AS base-rootfs

RUN apk add --no-cache bash qemu-guest-agent util-linux-misc

COPY init /init

####################

FROM alpine AS initramfs

COPY --from=base-rootfs / /rootfs

RUN cd /rootfs && \
    find . -print0 | cpio --null -ovt --format=newc | gzip -9 > /rootfs

####################

FROM scratch AS out-initramfs

COPY --from=initramfs /initramfs /

####################

FROM scratch AS out-rootfs

COPY --from=base-rootfs --link / /

FROM gcc:14.2.0 AS libpcap

RUN apt-get update && \
    apt-get install -y flex bison && \
    rm -r /var/lib/apt/*

ENV LIBPCAP_VERSION=1.10.4
RUN wget http://www.tcpdump.org/release/libpcap-${LIBPCAP_VERSION}.tar.gz && \
    tar xvf libpcap-${LIBPCAP_VERSION}.tar.gz && \
    cd libpcap-${LIBPCAP_VERSION} && \
    ./configure --enable-dbus=no && \
    make && \
    mkdir /build && \
    DESTDIR=/build make install

####################

FROM golang:1.23.0 AS dev

COPY --from=libpcap --link /build/usr/local/lib/* /usr/local/lib/
COPY --from=libpcap --link /build/usr/local/include/* /usr/local/include/
COPY --from=libpcap --link /build/usr/local/include/pcap/ /usr/local/include/pcap/

# We need to target specific kernel functions, so we need pwru to watch which
# kernel functions are called for a specific flow.
COPY --from=albinkerouanton006/pwru:latest --link /usr/local/bin/pwru /usr/local/bin/pwru

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      bpftool \
      bsdextrautils \
      clang-16 \
      iproute2 \
      less \
      linux-headers-generic \
      tcpdump \
      tshark && \
    rm -rf /var/lib/apt/* && \
    ln -s /usr/bin/clang-16 /usr/bin/clang

RUN go install github.com/go-delve/delve/cmd/dlv@latest && \
    go install github.com/essentialkaos/aligo/v2@latest

COPY ./hack/entrypoint.sh /entrypoint.sh
ENV AUTO_MOUNT=1
ENTRYPOINT ["/entrypoint.sh"]

####################

FROM golang:1.23.0 AS build

COPY --from=libpcap --link /build/usr/local/lib/* /usr/local/lib/
COPY --from=libpcap --link /build/usr/local/include/* /usr/local/include/
COPY --from=libpcap --link /build/usr/local/include/pcap/ /usr/local/include/pcap/

WORKDIR /skbdump

COPY . .
RUN ./hack/make.sh bpf binary

####################

FROM alpine:3.20 AS final

COPY --from=build /skbdump/bin/skbdump /bin/
COPY ./hack/entrypoint.sh /entrypoint.sh

ENV AUTO_MOUNT=1
ENTRYPOINT ["/entrypoint.sh"]

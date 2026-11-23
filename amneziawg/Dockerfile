# syntax=docker/dockerfile:1

ARG BUILD_FROM=ghcr.io/home-assistant/base:3.24
ARG GO_IMAGE=golang:1.25.12-alpine
ARG ALPINE_IMAGE=alpine:3.24

FROM ${GO_IMAGE} AS go-build
ARG AWG_GO_REF=v3.1.20261116
ARG AWG_GO_SHA256=5390f79949b9972669d006de95778ea9883fc16f7712a8b9ebfe63f96b52cf57
RUN apk add --no-cache ca-certificates curl \
 && curl -fsSL -o /tmp/awg-go.tar.gz \
      "https://github.com/amnezia-vpn/amneziawg-go/archive/refs/tags/${AWG_GO_REF}.tar.gz" \
 && echo "${AWG_GO_SHA256}  /tmp/awg-go.tar.gz" | sha256sum -c - \
 && mkdir -p /src/awg-go \
 && tar -xzf /tmp/awg-go.tar.gz -C /src/awg-go --strip-components=1
WORKDIR /src/awg-go
# -p 1 keeps the on-device Home Assistant build under the memory of a small board.
RUN mkdir -p /out \
 && printf 'package main\n\nconst Version = "%s"\n' "${AWG_GO_REF}" > version.go \
 && CGO_ENABLED=0 go build -p 1 -trimpath -ldflags="-s -w" -o /out/amneziawg-go .

FROM ${ALPINE_IMAGE} AS tools-build
ARG AWG_TOOLS_REF=v3.1.20260812
ARG AWG_TOOLS_SHA256=dbd8ce0748d835d18f30bb76720246b7bfc80bd09cd17c379b1c59f683a18493
RUN apk add --no-cache build-base ca-certificates curl linux-headers \
 && curl -fsSL -o /tmp/awg-tools.tar.gz \
      "https://github.com/amnezia-vpn/amneziawg-tools/archive/refs/tags/${AWG_TOOLS_REF}.tar.gz" \
 && echo "${AWG_TOOLS_SHA256}  /tmp/awg-tools.tar.gz" | sha256sum -c - \
 && mkdir -p /src/awg-tools \
 && tar -xzf /tmp/awg-tools.tar.gz -C /src/awg-tools --strip-components=1 \
 && make -C /src/awg-tools/src \
 && mkdir -p /out \
 && install -m 0755 /src/awg-tools/src/wg /out/awg

FROM ${ALPINE_IMAGE} AS snoop-build
RUN apk add --no-cache build-base linux-headers libpcap-dev
COPY src/dns-snoop.c /src/dns-snoop.c
RUN mkdir -p /out \
 && cc -O2 -Wall -Wextra -o /out/dns-snoop /src/dns-snoop.c -lpcap

FROM ${BUILD_FROM}
ARG BUILD_ARCH
ARG BUILD_VERSION
ARG AWG_GO_REF=v3.1.20261116
ARG AWG_TOOLS_REF=v3.1.20260812
RUN apk add --no-cache \
      bash \
      bind-tools \
      curl \
      iproute2 \
      jq \
      libpcap \
      nftables
COPY --from=go-build /out/amneziawg-go /usr/bin/amneziawg-go
COPY --from=tools-build /out/awg /usr/bin/awg
COPY --from=snoop-build /out/dns-snoop /usr/bin/dns-snoop
COPY rootfs /
RUN find /etc/s6-overlay/s6-rc.d -type f \( -name run -o -name finish \) -exec chmod 755 {} + \
 && chmod 755 /usr/bin/awg-up /usr/bin/awg-down /usr/bin/awg-tun /usr/bin/awg-dns \
      /usr/bin/awg-monitor /usr/bin/awg-health /usr/bin/awg-finish /usr/lib/awg/health-respond
ENV S6_KILL_GRACETIME=8000 \
    S6_KILL_FINISH_MAXTIME=8000 \
    S6_SERVICES_GRACETIME=8000
LABEL \
  io.hass.name="amneziawg" \
  io.hass.description="Selective AmneziaWG client" \
  io.hass.arch="${BUILD_ARCH}" \
  io.hass.type="addon" \
  io.hass.version="${BUILD_VERSION}" \
  org.opencontainers.image.source="https://github.com/Waitancheg/ha-awg-routing" \
  org.opencontainers.image.licenses="MIT" \
  org.opencontainers.image.version="${AWG_GO_REF}+${AWG_TOOLS_REF}"

# syntax=docker/dockerfile:1
FROM golang:1.25-bookworm AS go-build
ARG AWG_GO_COMMIT
RUN test "${#AWG_GO_COMMIT}" = 40 \
    && git init /src && cd /src \
    && git remote add origin https://github.com/amnezia-vpn/amneziawg-go.git \
    && git fetch --depth=1 origin "$AWG_GO_COMMIT" \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "$AWG_GO_COMMIT"
WORKDIR /src
RUN CGO_ENABLED=0 go build -trimpath -o /out/amneziawg-go .

FROM debian:bookworm-slim AS tools-build
ARG AWG_TOOLS_COMMIT
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git build-essential \
    && rm -rf /var/lib/apt/lists/*
RUN test "${#AWG_TOOLS_COMMIT}" = 40 \
    && git init /src && cd /src \
    && git remote add origin https://github.com/amnezia-vpn/amneziawg-tools.git \
    && git fetch --depth=1 origin "$AWG_TOOLS_COMMIT" \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "$AWG_TOOLS_COMMIT" \
    && make -C src -j2

FROM debian:bookworm-slim
ARG AWG_GO_COMMIT
ARG AWG_TOOLS_COMMIT
LABEL org.opencontainers.image.title="Aegis AmneziaWG server" \
      org.aegis.awg-go.commit=$AWG_GO_COMMIT \
      org.aegis.awg-tools.commit=$AWG_TOOLS_COMMIT
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates iproute2 iptables python3 python3-cryptography \
    && rm -rf /var/lib/apt/lists/*
COPY --from=go-build /out/amneziawg-go /usr/local/bin/amneziawg-go
COPY --from=tools-build /src/src/wg /usr/local/bin/awg
COPY --from=go-build /src/LICENSE /usr/share/doc/amneziawg-go/LICENSE
COPY --from=tools-build /src/COPYING /usr/share/doc/amneziawg-tools/COPYING
WORKDIR /opt/aegis
COPY agent.py entrypoint.py ./
EXPOSE 51820/udp 8787/tcp
ENTRYPOINT ["python3", "/opt/aegis/entrypoint.py"]

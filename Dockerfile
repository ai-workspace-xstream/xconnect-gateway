FROM golang:1.26.4-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /out/xconnect-gateway ./cmd/xconnect-gateway

FROM debian:bookworm-slim AS xray
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) asset=Xray-linux-64.zip; sha=23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae ;; \
      arm64) asset=Xray-linux-arm64-v8a.zip; sha=4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c ;; \
      *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL --retry 3 "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/${asset}" -o /tmp/xray.zip; \
    echo "${sha}  /tmp/xray.zip" | sha256sum -c -; \
    unzip -j /tmp/xray.zip xray -d /out; \
    chmod 0755 /out/xray

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates iproute2 iptables wireguard-tools && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/xconnect-gateway /usr/local/bin/
COPY --from=xray /out/xray /usr/local/bin/
EXPOSE 443/tcp
ENTRYPOINT ["/usr/local/bin/xconnect-gateway"]
CMD ["serve"]

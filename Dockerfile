# syntax=docker/dockerfile:1.7
FROM golang:1.27.0-alpine3.23 AS go-dependencies
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

FROM go-dependencies AS setup-helper-builder
COPY cmd/setup-helper/ ./cmd/setup-helper/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/setup-helper ./cmd/setup-helper

FROM scratch AS setup-helper
COPY --from=setup-helper-builder /out/setup-helper /setup-helper
ENTRYPOINT ["/setup-helper"]

FROM node:24.11.1-alpine3.23 AS frontend-builder
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM go-dependencies AS go-builder
ARG VERSION=dev
COPY . .
COPY --from=frontend-builder /src/internal/webui/dist ./internal/webui/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/certmate ./cmd/server

FROM alpine:3.23 AS acmesh
ARG ACME_SH_VERSION=3.1.4
ARG ACME_SH_SHA256=e5f8e187bbf5251e0cd8891f2622daab9850366bd17bea9f92c2fe2ee091fd32
RUN wget -qO /tmp/acme.tar.gz "https://github.com/acmesh-official/acme.sh/archive/refs/tags/${ACME_SH_VERSION}.tar.gz" \
    && echo "${ACME_SH_SHA256}  /tmp/acme.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/acme.sh \
    && tar -xzf /tmp/acme.tar.gz --strip-components=1 -C /opt/acme.sh \
    && rm /tmp/acme.tar.gz

FROM alpine:3.23 AS runtime
RUN apk add --no-cache ca-certificates openssl tzdata curl socat \
    && addgroup -S -g 10001 certmate \
    && adduser -S -D -H -u 10001 -G certmate certmate \
    && mkdir -p /app /data/acme /data/challenges /data/logs /data/temp /data/backups /certs \
    && chown -R certmate:certmate /app /data /certs
COPY --from=go-builder --chown=certmate:certmate /out/certmate /app/certmate
COPY --from=acmesh --chown=certmate:certmate /opt/acme.sh /opt/acme.sh
COPY --chown=certmate:certmate LICENSE THIRD_PARTY_NOTICES.md /licenses/
ENV PATH="/opt/acme.sh:${PATH}"
USER certmate:certmate
EXPOSE 8080
VOLUME ["/data", "/certs"]
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/app/certmate", "healthcheck"]
ENTRYPOINT ["/app/certmate"]

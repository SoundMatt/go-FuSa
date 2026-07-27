# syntax=docker/dockerfile:1
#
# Multi-stage build for go-FuSa.
# Stage 1 compiles the gofusa binary; Stage 2 produces a minimal runtime image.
#
# Build:
#   docker build -t go-fusa .
#
# Run (mount your project at /project):
#   docker run --rm -v "$(pwd)":/project go-fusa check
#   docker run --rm -v "$(pwd)":/project go-fusa trace
#   docker run --rm -v "$(pwd)":/project go-fusa verify
#   docker run --rm -v "$(pwd)":/project go-fusa release

# Image label values. Overridden at CI build time via --build-arg (see
# .github/workflows/docker-publish.yml) so they always track fusa.go's
# Version/SpecVersion constants instead of going stale in this file. The
# defaults below are best-effort for plain local `docker build` runs.
ARG VERSION=0.33.5
ARG SPEC_VERSION=1.10.12

# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Copy dependency manifest first for layer-cache efficiency.
COPY go.mod ./

# Copy the full source tree.
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -extldflags=-static" \
    -o /bin/gofusa \
    ./cmd/gofusa

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM alpine:3.20

# Re-declare to bring the global ARGs (and any --build-arg override) into
# this stage's scope; Docker clears ARG scope at each FROM.
ARG VERSION
ARG SPEC_VERSION

# git is needed for provenance VCS info; ca-certificates for TLS.
RUN apk add --no-cache git ca-certificates

COPY --from=builder /bin/gofusa /usr/local/bin/gofusa

LABEL org.opencontainers.image.title="go-FuSa" \
      org.opencontainers.image.description="Functional safety enablement toolkit for Go" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/SoundMatt/go-FuSa" \
      org.opencontainers.image.licenses="MPL-2.0" \
      io.x-fusa.tool="go-FuSa" \
      io.x-fusa.language="go" \
      io.x-fusa.binary="gofusa" \
      io.x-fusa.spec-version="${SPEC_VERSION}"

# Default working directory is /project; mount your Go project here.
WORKDIR /project

ENTRYPOINT ["gofusa"]
CMD ["help"]

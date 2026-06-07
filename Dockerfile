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

# git is needed for provenance VCS info; ca-certificates for TLS.
RUN apk add --no-cache git ca-certificates

COPY --from=builder /bin/gofusa /usr/local/bin/gofusa

# Default working directory is /project; mount your Go project here.
WORKDIR /project

ENTRYPOINT ["gofusa"]
CMD ["help"]

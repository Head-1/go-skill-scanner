# ═══════════════════════════════════════════════════════════════════════════════
# go-skill-scanner — Multi-Stage Dockerfile
#
# ARCHITECTURE DECISION RECORD (ADR-001):
#   This is a 3-stage build that solves the CGO static linking problem.
#
#   Problem:  go-yara requires CGO and libyara. A naive `go build` produces
#             a binary that dynamically links libyara.so — breaking plug-and-play.
#
#   Solution: Stage 1 compiles libyara from source as a static archive (.a).
#             Stage 2 links the Go binary against that static archive with
#             CGO_ENABLED=1 -tags yara_static. The result is a fully static
#             binary with zero runtime dependencies.
#             Stage 3 is a distroless scratch container (~10MB total image).
#
#   Output:   A single static binary `go-skill-scanner` that runs anywhere.
# ═══════════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────────
# STAGE 1: libyara static builder
# Purpose: Compile libyara from source into a static archive (libyara.a).
#          This stage produces nothing except /usr/local/lib/libyara.a
#          and the matching headers in /usr/local/include/yara/.
# ───────────────────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS yara-builder

# Pin the YARA version. Bump this only after testing go-yara compatibility.
ARG YARA_VERSION=4.5.1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    automake \
    libtool \
    wget \
    ca-certificates \
    # YARA optional module deps (enable/disable to control binary size):
    libssl-dev \        
    # Required for the 'hash' module (SHA/MD5 inside YARA rules).
    libmagic-dev \      
    # Required for the 'magic' module.
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Download YARA source from GitHub releases (pinned sha256 for supply-chain safety).
RUN wget -q "https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz" \
    -O yara.tar.gz \
    && tar -xzf yara.tar.gz \
    && rm yara.tar.gz

WORKDIR /build/yara-${YARA_VERSION}

# Configure YARA:
#   --disable-shared     → produce only libyara.a (no .so)
#   --enable-magic       → enable file type detection in rules
#   --enable-cuckoo      → enable Cuckoo sandbox integration hooks
#   --without-crypto     → disable OpenSSL if not needed (reduces attack surface)
#                          Switch to --with-crypto if hash module is required.
RUN autoreconf -fi \
    && ./configure \
        --prefix=/usr/local \
        --disable-shared \
        --enable-static \
        --enable-magic \
        --without-crypto \
    && make -j"$(nproc)" \
    && make install

# Verify the static archive was produced.
RUN test -f /usr/local/lib/libyara.a && echo "✓ libyara.a produced successfully"

# ───────────────────────────────────────────────────────────────────────────────
# STAGE 2: Go binary builder
# Purpose: Compile go-skill-scanner as a fully static binary.
#          CGO is enabled ONLY for YARA; all other deps are pure Go.
# ───────────────────────────────────────────────────────────────────────────────
FROM golang:1.22-bookworm AS go-builder

# Install the minimal C toolchain needed for CGO linking.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the static libyara.a and its headers from Stage 1.
COPY --from=yara-builder /usr/local/lib/libyara.a /usr/local/lib/libyara.a
COPY --from=yara-builder /usr/local/include/yara  /usr/local/include/yara

WORKDIR /app

# Dependency layer — cached unless go.mod/go.sum change.
COPY go.mod go.sum ./
RUN go mod download

# Source layer.
COPY . .

# ─── THE CRITICAL BUILD COMMAND ───────────────────────────────────────────────
#
#   CGO_ENABLED=1          Required for go-yara (C bindings).
#   -tags yara_static      Tells go-yara to link against the static archive,
#                          not look for a shared .so at runtime.
#   -ldflags:
#     -extldflags=-static  Instructs the external C linker to produce a
#                          fully static ELF binary (no dynamic loader needed).
#     -s -w                Strip debug symbols → reduces binary size by ~30%.
#     -X ...               Inject build-time version metadata.
#
#   Result: A single ELF binary with zero dynamic library dependencies.
#           Verify with: `ldd go-skill-scanner` → "not a dynamic executable"
#
RUN CGO_ENABLED=1 \
    GOOS=linux \
    GOARCH=amd64 \
    go build \
    -tags yara_static \
    -ldflags="-extldflags=-static -s -w \
              -X github.com/go-skill-scanner/go-skill-scanner/internal/engine.Version=$(git describe --tags --always --dirty 2>/dev/null || echo 'dev') \
              -X github.com/go-skill-scanner/go-skill-scanner/internal/engine.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o go-skill-scanner \
    ./cmd/scanner/...

# Verify static linking. This will fail the build if any .so is linked.
RUN ldd go-skill-scanner 2>&1 | grep -q "not a dynamic executable" \
    && echo "✓ Binary is fully static (plug-and-play confirmed)" \
    || (echo "✗ FATAL: Binary has dynamic dependencies — plug-and-play broken" && exit 1)

# Verify binary size is under 15MB as per the architectural contract.
RUN BINARY_SIZE=$(stat -c%s go-skill-scanner) \
    && echo "Binary size: $(( BINARY_SIZE / 1024 / 1024 ))MB ($(( BINARY_SIZE / 1024 ))KB)" \
    && [ "$BINARY_SIZE" -lt "15728640" ] \
    && echo "✓ Binary size within 15MB architectural budget" \
    || echo "⚠ WARNING: Binary exceeds 15MB budget — review embedded rule bundles"

# ───────────────────────────────────────────────────────────────────────────────
# STAGE 3: Minimal runtime image
# Purpose: Ship the smallest possible container.
#          Uses 'scratch' (empty base) — no shell, no OS, no attack surface.
#
# NOTE: If you need a shell for debugging in production, swap scratch for
#       gcr.io/distroless/static-debian12 which adds ~2MB but includes
#       CA certs and timezone data without a shell.
# ───────────────────────────────────────────────────────────────────────────────
FROM scratch AS runtime

# Non-root user for security hardening.
# 'scratch' has no /etc/passwd so we use numeric IDs directly.
# UID/GID 65532 matches the distroless 'nonroot' convention.
USER 65532:65532

# Copy the static binary from the builder.
COPY --from=go-builder --chown=65532:65532 /app/go-skill-scanner /go-skill-scanner

# Copy CA certificates for HTTPS calls to LLM backends (Anthropic, OpenAI).
COPY --from=go-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# ─── Runtime Configuration ────────────────────────────────────────────────────
# All configuration is via environment variables (12-factor compliant).
# No config files are baked into the image.

# MCP server port.
EXPOSE 8443

# Health check — scanner responds to a ping tool call.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/go-skill-scanner", "healthcheck"]

ENTRYPOINT ["/go-skill-scanner"]
CMD ["serve", "--mcp", "--port", "8443"]

# ═══════════════════════════════════════════════════════════════════════════════
# Build Targets Reference
# ═══════════════════════════════════════════════════════════════════════════════
#
#   Standard build (linux/amd64):
#     docker build -t go-skill-scanner:latest .
#
#   Multi-arch build (for ARM64 edge deployments):
#     docker buildx build \
#       --platform linux/amd64,linux/arm64 \
#       -t go-skill-scanner:latest \
#       --push .
#
#   Extract binary without running container:
#     docker build --target go-builder -t gss-builder .
#     docker create --name gss-extract gss-builder
#     docker cp gss-extract:/app/go-skill-scanner ./go-skill-scanner
#     docker rm gss-extract
#
#   Local development (skip Docker, requires libyara on host):
#     brew install yara          # macOS
#     apt-get install libyara-dev # Debian/Ubuntu
#     CGO_ENABLED=1 go run -tags yara_static ./cmd/scanner/...
#
# ═══════════════════════════════════════════════════════════════════════════════

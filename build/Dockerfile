# ═══════════════════════════════════════════════════════════════════════════════
# go-skill-scanner — Multi-Stage Dockerfile (v7)
# Corrigido: Link estático com todas as dependências do YARA (jansson, magic)
# ═══════════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────────
# STAGE 1: libyara static builder
# ───────────────────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS yara-builder

ARG YARA_VERSION=4.5.1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    automake \
    autoconf \
    libtool \
    wget \
    ca-certificates \
    pkg-config \
    flex \
    bison \
    libssl-dev \
    libmagic-dev \
    libjansson-dev \
    libprotobuf-c-dev \
    protobuf-c-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

RUN wget -q "https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz" \
    -O yara.tar.gz \
    && tar -xzf yara.tar.gz \
    && rm yara.tar.gz

WORKDIR /build/yara-${YARA_VERSION}

# Desabilitar módulos que causam dependências extras (cuckoo, dotnet, magic)
RUN autoreconf -fi \
    && ./configure \
        --prefix=/usr/local \
        --disable-shared \
        --enable-static \
        --disable-cuckoo \
        --disable-dotnet \
        --disable-magic \
        --without-crypto \
    && make -j"$(nproc)" \
    && make install

# Criar yara.pc manualmente
RUN mkdir -p /usr/local/lib/pkgconfig && \
    cat > /usr/local/lib/pkgconfig/yara.pc << 'EOF'
prefix=/usr/local
exec_prefix=${prefix}
libdir=${exec_prefix}/lib
includedir=${prefix}/include

Name: yara
Description: YARA is a pattern matching swiss army knife
Version: 4.5.1
Requires:
Libs: -L${libdir} -lyara -lm
Cflags: -I${includedir}
EOF

# Verificar instalação
RUN test -f /usr/local/lib/libyara.a && echo "✓ libyara.a" || exit 1
RUN test -f /usr/local/lib/pkgconfig/yara.pc && echo "✓ yara.pc" || exit 1
RUN test -f /usr/local/include/yara.h && echo "✓ yara.h" || exit 1

# ───────────────────────────────────────────────────────────────────────────────
# STAGE 2: Go binary builder
# ───────────────────────────────────────────────────────────────────────────────
FROM golang:1.25-bookworm AS go-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copiar libyara estática e headers
COPY --from=yara-builder /usr/local/lib/libyara.a /usr/local/lib/libyara.a
COPY --from=yara-builder /usr/local/include /usr/local/include
COPY --from=yara-builder /usr/local/lib/pkgconfig /usr/local/lib/pkgconfig

# Configurar pkg-config e flags
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
ENV CGO_CFLAGS="-I/usr/local/include"
ENV CGO_LDFLAGS="-L/usr/local/lib -lyara -lm -static"

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build com flags explícitas
RUN CGO_ENABLED=1 \
    GOOS=linux \
    GOARCH=amd64 \
    CGO_CFLAGS="-I/usr/local/include" \
    CGO_LDFLAGS="-L/usr/local/lib -lyara -lm -static" \
    go build \
    -tags yara_static \
    -ldflags="-extldflags=-static -s -w" \
    -o gss-daemon \
    ./cmd/scanner

# Verificar linking estático
RUN ldd gss-daemon 2>&1 | grep -q "not a dynamic executable" \
    && echo "✓ Binary is fully static" \
    || (echo "✗ FATAL: Binary has dynamic dependencies" && ldd gss-daemon && exit 1)

# ───────────────────────────────────────────────────────────────────────────────
# STAGE 3: Runtime image (minimal)
# ───────────────────────────────────────────────────────────────────────────────
FROM alpine:3.19 AS runtime

RUN apk add --no-cache sqlite

RUN mkdir -p /data && \
    adduser -D -u 65532 -h /app scanner && \
    chown -R scanner:scanner /data

COPY --from=go-builder --chown=scanner:scanner /app/gss-daemon /app/gss-daemon
COPY --from=go-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

WORKDIR /app

USER scanner

ENTRYPOINT ["/app/gss-daemon"]
CMD ["mcp", "--audit-db", "/data/gss.db"]

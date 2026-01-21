# =============================================================================
# Post-Quantum VPN Router - Kyber Native (Open Source)
# =============================================================================
# Full source code - MIT License
# Enterprise support: grant@abejar.net
# =============================================================================

FROM alpine:3.19 AS builder

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    cmake \
    git \
    linux-headers \
    openssl-dev \
    libmnl-dev \
    ninja

# Build liboqs (Open Quantum Safe)
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /liboqs && \
    cd /liboqs && \
    mkdir build && cd build && \
    cmake -GNinja \
        -DOQS_MINIMAL_BUILD="KEM_kyber_1024" \
        -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        .. && \
    ninja && \
    ninja install

# Build WireGuard tools
RUN git clone --depth 1 https://git.zx2c4.com/wireguard-tools /wg-tools && \
    cd /wg-tools/src && \
    make && \
    make install DESTDIR=/wg-install

# Production image
FROM linuxserver/wireguard:latest

LABEL maintainer="Abejar <grant@abejar.net>"
LABEL description="Post-Quantum VPN Router with Kyber-1024 (Open Source)"
LABEL license="MIT"

# Copy liboqs
COPY --from=builder /usr/local/lib/liboqs* /usr/local/lib/
COPY --from=builder /usr/local/include/oqs /usr/local/include/oqs

# Install runtime dependencies
RUN apk add --no-cache \
    curl \
    jq \
    openssl \
    python3 \
    bash \
    ca-certificates

# Create directories
RUN mkdir -p /opt/pqc/bin /opt/pqc/lib

# Copy PQC wrapper scripts (FULL SOURCE)
COPY pqc-lib/kyber-wrapper.sh /opt/pqc/bin/
COPY config/routing/setup-routes.sh /opt/pqc/bin/
COPY entrypoint-pqc.sh /opt/pqc/bin/
COPY healthcheck.sh /healthcheck.sh

# Set permissions
RUN chmod +x /opt/pqc/bin/* /healthcheck.sh

# Update library path
ENV LD_LIBRARY_PATH=/usr/local/lib
ENV PQC_ENABLED=true
ENV PQC_ALGORITHM=kyber1024

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD /healthcheck.sh

ENTRYPOINT ["/init"]

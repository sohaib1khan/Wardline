# Wardline scanner image — pinned base + checksum-verified Trivy.
# Never install Trivy 0.69.4 / 0.69.5 / 0.69.6 (supply-chain denylist).

# debian:bookworm-slim (amd64) — pin by digest
ARG DEBIAN_DIGEST=sha256:311f7a192fd9a92b165a86b32fa3aae9005b11849bfb1db2d4fd784559ee464f
FROM debian:bookworm-slim@${DEBIAN_DIGEST}

LABEL org.opencontainers.image.title="wardline-scanner"
LABEL org.opencontainers.image.description="Wardline scanner sidecar (tools via docker exec; host at /host)"

ENV DEBIAN_FRONTEND=noninteractive \
    TRIVY_CACHE_DIR=/var/lib/trivy \
    LANG=C.UTF-8

# Pinned Trivy release (not denylisted). Checksum of Linux-64bit.tar.gz from GitHub.
ARG TRIVY_VERSION=0.76.2
ARG TRIVY_TAR_SHA256=bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        python3 \
        python3-pip \
        python3-venv \
        iproute2 \
        procps \
        util-linux \
        nmap \
        clamav \
        clamav-freshclam \
        lynis \
        rkhunter \
        chkrootkit \
        aide \
        aide-common \
        debsums \
        needrestart \
        libopenscap8 \
        openscap-scanner \
        net-tools \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy from the official release tarball with SHA-256 verification.
RUN set -eux; \
    curl -fsSL -o /tmp/trivy.tar.gz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
    echo "${TRIVY_TAR_SHA256}  /tmp/trivy.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy; \
    chmod 0755 /usr/local/bin/trivy; \
    rm -f /tmp/trivy.tar.gz; \
    trivy --version; \
    mkdir -p /var/lib/trivy /var/lib/clamav

WORKDIR /opt/wardline
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip3 install --no-cache-dir --break-system-packages . \
    && wardline --version

COPY docker/entrypoint.sh /usr/local/bin/wardline-entrypoint.sh
RUN chmod 0755 /usr/local/bin/wardline-entrypoint.sh

# Default: long-lived scanner sidecar (tools invoked via `docker exec`).
# Override CMD to run Wardline inside the container (alternate mode).
ENTRYPOINT ["/usr/local/bin/wardline-entrypoint.sh"]
CMD ["sleep", "infinity"]

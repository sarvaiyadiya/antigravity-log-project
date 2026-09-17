# ============================================================================
# ULPF — Universal Log Pre-processing Framework
# Multi-stage Dockerfile for air-gap deployable container
#
# PS requirement (j): Deployable in an air-gapped network
# PS requirement (k): Packaged in a container for platform independence
#
# Build:   docker build -t ulpf:latest .
# Run:     docker run -v /path/to/logs:/data/raw ulpf:latest ingest \
#              --source configs/sources/syslog_firewall.yaml \
#              --output-format json-lines
# ============================================================================

# ---------------------------------------------------------------------------
# Stage 1: dependency builder
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS builder

# Install build dependencies (only needed during build)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy requirements first (layer cache efficiency)
COPY requirements.txt .

# Install dependencies into a prefix directory
# --no-build-isolation avoids network calls during builds in air-gap envs
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: minimal runtime image
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

LABEL maintainer="ULPF Development Team"
LABEL description="Universal Log Pre-processing Framework"
LABEL version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/your-org/ulpf"

# Security: run as non-root user
RUN groupadd -r ulpf && useradd -r -g ulpf -m -d /app ulpf

WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY --chown=ulpf:ulpf src/ ./src/
COPY --chown=ulpf:ulpf configs/ ./configs/

# Create necessary directories with correct permissions
RUN mkdir -p \
    data/raw \
    data/interim \
    data/processed \
    data/labels \
    data/features \
    data/balancing \
    data/aggregated \
    outputs/normalized \
    && chown -R ulpf:ulpf data/ outputs/

# Set Python path so imports work
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Switch to non-root user
USER ulpf

# Default entrypoint: run as module
ENTRYPOINT ["python", "-m", "src"]

# Default command: show help
CMD ["--help"]

# ---------------------------------------------------------------------------
# Health check: verify the framework can list parsers
# ---------------------------------------------------------------------------
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -m src parsers > /dev/null 2>&1 || exit 1

# ---------------------------------------------------------------------------
# Exposed volumes
# ---------------------------------------------------------------------------
# /app/data/raw    — mount your log files here
# /app/outputs     — mount output directory here

VOLUME ["/app/data/raw", "/app/outputs"]

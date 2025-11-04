# Multi-stage Dockerfile for NetFlow to OpenTelemetry Traces
# Uses modern uv sync pattern with lockfile for reproducible builds

# Build stage - using official uv image with Python 3.14
FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim AS builder

# Set working directory
WORKDIR /app

# Enable bytecode compilation for faster startup
ENV UV_COMPILE_BYTECODE=1

# Use copy mode for reproducible builds in containers
ENV UV_LINK_MODE=copy

# Install dependencies first (better caching - changes rarely)
# Mount cache for faster subsequent builds
# Only mount the files needed for dependency resolution
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project --no-dev

# Copy all source code (changes frequently, separate layer)
COPY . /app

# Install the project itself
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# Runtime stage - minimal Python 3.14 image
FROM python:3.14-slim

# Install runtime dependencies
# Scapy requires libpcap for packet capture functionality
# procps provides pgrep for health check
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libpcap0.8 \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 netflow && \
    mkdir -p /app && \
    chown -R netflow:netflow /app

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder --chown=netflow:netflow /app/.venv /app/.venv

# Copy source code from builder
# This is required because the package is installed in the venv with references to /app/src/
COPY --from=builder --chown=netflow:netflow /app/src /app/src
COPY --from=builder --chown=netflow:netflow /app/pyproject.toml /app/pyproject.toml

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Switch to non-root user
USER netflow

# Expose NetFlow UDP port
EXPOSE 2055/udp

# Health check - verify the process is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep -f "python -m netflow2traces" || exit 1

# Run the application
CMD ["python", "-m", "netflow2traces"]
